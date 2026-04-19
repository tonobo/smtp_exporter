// Package smtpfake spins up an in-process SMTP server for tests.
package smtpfake

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	sasl "github.com/emersion/go-sasl"
	esmtp "github.com/emersion/go-smtp"
)

// Backend defines the per-test behavior of the fake SMTP server.
// Any handler may be left nil — defaults are no-op auth/from/rcpt and
// reading-DATA-and-discarding.
type Backend struct {
	OnAuth func(username, password string) error
	OnMail func(from string) error
	OnRcpt func(to string) error
	OnData func(raw []byte) error
}

// Fake is a running fake SMTP server.
type Fake struct {
	Addr string

	mu   sync.Mutex
	last struct {
		From, To string
		Data     []byte
	}
}

// LastData returns the (from, to, data) of the last DATA command; thread-safe.
func (f *Fake) LastData() (from, to string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last.From, f.last.To, append([]byte(nil), f.last.Data...)
}

// Start boots a plain-text fake SMTP server.
func Start(t *testing.T, b Backend) *Fake {
	t.Helper()
	return startWith(t, b, nil)
}

// StartTLS boots a fake SMTP server that advertises STARTTLS using the given TLS config.
func StartTLS(t *testing.T, b Backend, tlsCfg *tls.Config) *Fake {
	t.Helper()
	return startWith(t, b, tlsCfg)
}

func startWith(t *testing.T, b Backend, tlsCfg *tls.Config) *Fake {
	t.Helper()
	f := &Fake{}
	backend := &fakeBackend{f: f, ext: b}
	srv := esmtp.NewServer(backend)
	srv.Domain = "test.localhost"
	srv.AllowInsecureAuth = true
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
	}

	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	if err != nil {
		t.Fatalf("smtpfake: listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	f.Addr = l.Addr().String()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close() })
	return f
}

// StartDirectTLS boots a fake SMTP server on a TLS listener (implicit TLS, not STARTTLS).
func StartDirectTLS(t *testing.T, b Backend, tlsCfg *tls.Config) *Fake {
	t.Helper()
	f := &Fake{}
	backend := &fakeBackend{f: f, ext: b}
	srv := esmtp.NewServer(backend)
	srv.Domain = "test.localhost"
	srv.AllowInsecureAuth = true
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second

	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("smtpfake: tls listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	f.Addr = l.Addr().String()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close() })
	return f
}

// fakeBackend implements esmtp.Backend.
type fakeBackend struct {
	f   *Fake
	ext Backend
}

func (b *fakeBackend) NewSession(_ *esmtp.Conn) (esmtp.Session, error) {
	return &fakeSession{b: b}, nil
}

type fakeSession struct{ b *fakeBackend }

func (s *fakeSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *fakeSession) Auth(_ string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, username, password string) error {
		if s.b.ext.OnAuth != nil {
			return s.b.ext.OnAuth(username, password)
		}
		return nil
	}), nil
}
func (s *fakeSession) Mail(from string, _ *esmtp.MailOptions) error {
	s.b.f.mu.Lock()
	s.b.f.last.From = from
	s.b.f.mu.Unlock()
	if s.b.ext.OnMail != nil {
		return s.b.ext.OnMail(from)
	}
	return nil
}
func (s *fakeSession) Rcpt(to string, _ *esmtp.RcptOptions) error {
	s.b.f.mu.Lock()
	s.b.f.last.To = to
	s.b.f.mu.Unlock()
	if s.b.ext.OnRcpt != nil {
		return s.b.ext.OnRcpt(to)
	}
	return nil
}
func (s *fakeSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.b.f.mu.Lock()
	s.b.f.last.Data = raw
	s.b.f.mu.Unlock()
	if s.b.ext.OnData != nil {
		return s.b.ext.OnData(raw)
	}
	return nil
}
func (*fakeSession) Reset()        {}
func (*fakeSession) Logout() error { return nil }
