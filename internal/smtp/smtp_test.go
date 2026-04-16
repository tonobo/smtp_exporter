package smtp

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	sasl "github.com/emersion/go-sasl"
	esmtp "github.com/emersion/go-smtp"
)

type testBackend struct {
	mu       sync.Mutex
	MailFrom string
	RcptTo   string
	Data     []byte
}

func (b *testBackend) NewSession(c *esmtp.Conn) (esmtp.Session, error) {
	return &testSession{b: b}, nil
}

type testSession struct{ b *testBackend }

func (s *testSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *testSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		return nil
	}), nil
}
func (s *testSession) Mail(from string, _ *esmtp.MailOptions) error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	s.b.MailFrom = from
	return nil
}
func (s *testSession) Rcpt(to string, _ *esmtp.RcptOptions) error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	s.b.RcptTo = to
	return nil
}
func (s *testSession) Data(r io.Reader) error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	b, err := io.ReadAll(r)
	s.b.Data = b
	return err
}
func (s *testSession) Reset()        {}
func (s *testSession) Logout() error { return nil }

// startTestServer starts a plain-text emersion SMTP server on a random port.
func startTestServer(t *testing.T) (string, *testBackend, func()) {
	t.Helper()
	be := &testBackend{}
	srv := esmtp.NewServer(be)
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	return l.Addr().String(), be, func() { srv.Close(); l.Close() }
}

func TestSend_PlainSuccess(t *testing.T) {
	addr, be, stop := startTestServer(t)
	defer stop()

	in := Input{
		Server:   addr,
		TLS:      "no",
		EHLO:     "client.local",
		MailFrom: "probe@example.org",
		MailTo:   "target@other.example",
		Data:     bytes.NewBufferString("Subject: x\r\n\r\nhi\r\n").Bytes(),
	}
	res, err := Send(context.Background(), in)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !res.Success {
		t.Fatal("expected success")
	}
	if be.MailFrom != "probe@example.org" || be.RcptTo != "target@other.example" {
		t.Fatalf("recv: %+v", be)
	}
}
