package smtp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
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
func (s *testSession) Auth(_ string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, username, password string) error {
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
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; context not meaningful for net.Listen
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String(), be, func() { _ = srv.Close(); _ = l.Close() }
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

// selfSignedTLSConfig generates a self-signed cert+key and returns a
// *tls.Config suitable for use as a server config and (with the cert in the
// RootCAs pool) as the matching client config.
func selfSignedTLSConfig(t *testing.T) (serverCfg, clientCfg *tls.Config) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}),
	)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)

	serverCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	clientCfg = &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	return serverCfg, clientCfg
}

// startTLSTestServer starts an emersion SMTP server that advertises and
// requires STARTTLS using the provided server TLS config.
func startTLSTestServer(t *testing.T, serverTLS *tls.Config) (addr string, stop func()) {
	t.Helper()
	be := &testBackend{}
	srv := esmtp.NewServer(be)
	srv.Domain = "localhost"
	srv.TLSConfig = serverTLS
	srv.AllowInsecureAuth = true
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String(), func() { _ = srv.Close(); _ = l.Close() }
}

// TestSend_StartTLSWithCustomCA verifies that Send succeeds when given a
// custom RootCAs pool containing the server's self-signed cert.
func TestSend_StartTLSWithCustomCA(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLSConfig(t)
	addr, stop := startTLSTestServer(t, serverTLS)
	defer stop()

	in := Input{
		Server:    addr,
		TLS:       "starttls",
		EHLO:      "client.local",
		MailFrom:  "probe@example.org",
		MailTo:    "target@other.example",
		Data:      bytes.NewBufferString("Subject: tls-test\r\n\r\nhi\r\n").Bytes(),
		TLSConfig: clientTLS,
	}
	res, err := Send(context.Background(), in)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got: code=%d msg=%q", res.StatusCode, res.Message)
	}
	if !res.UsedTLS {
		t.Fatal("expected UsedTLS=true for STARTTLS connection")
	}
}

// TestRecordSMTPErr_TruncatesLongMessage verifies that recordSMTPErr clamps
// Result.Message to maxMessageBytes and appends the truncation marker.
func TestRecordSMTPErr_TruncatesLongMessage(t *testing.T) {
	longMsg := strings.Repeat("a", 1000)
	se := &esmtp.SMTPError{Code: 554, Message: longMsg}
	var r Result
	recordSMTPErr(&r, se)
	if len(r.Message) > maxMessageBytes+len("…(truncated)") {
		t.Fatalf("message not truncated: len=%d", len(r.Message))
	}
	if !strings.HasSuffix(r.Message, "…(truncated)") {
		t.Fatalf("truncation marker missing: %q", r.Message)
	}
	if r.StatusCode != 554 {
		t.Fatalf("status code: %d", r.StatusCode)
	}
}

// rejectAuthBackend is an SMTP backend whose Auth handler always returns a 535.
type rejectAuthBackend struct{}

func (b *rejectAuthBackend) NewSession(_ *esmtp.Conn) (esmtp.Session, error) {
	return &rejectAuthSession{}, nil
}

type rejectAuthSession struct{}

func (s *rejectAuthSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *rejectAuthSession) Auth(_ string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, _, _ string) error {
		return &esmtp.SMTPError{Code: 535, Message: "5.7.8 Authentication credentials invalid"}
	}), nil
}
func (s *rejectAuthSession) Mail(_ string, _ *esmtp.MailOptions) error { return nil }
func (s *rejectAuthSession) Rcpt(_ string, _ *esmtp.RcptOptions) error { return nil }
func (s *rejectAuthSession) Data(_ io.Reader) error                    { return nil }
func (s *rejectAuthSession) Reset()                                    {}
func (s *rejectAuthSession) Logout() error                             { return nil }

// startRejectAuthServer starts a plain SMTP server that rejects all AUTH attempts.
func startRejectAuthServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	srv := esmtp.NewServer(&rejectAuthBackend{})
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String(), func() { _ = srv.Close(); _ = l.Close() }
}

// TestSend_AuthFailure verifies that Send correctly surfaces an AUTH error:
// Result.Success=false, StatusCode > 0, Message populated, and error non-nil.
func TestSend_AuthFailure(t *testing.T) {
	addr, stop := startRejectAuthServer(t)
	defer stop()

	in := Input{
		Server:   addr,
		TLS:      "no",
		EHLO:     "client.local",
		Username: "user@example.org",
		Password: "wrongpassword",
		MailFrom: "probe@example.org",
		MailTo:   "target@other.example",
		Data:     bytes.NewBufferString("Subject: auth-fail\r\n\r\nhi\r\n").Bytes(),
	}
	res, err := Send(context.Background(), in)
	if err == nil {
		t.Fatal("expected error from AUTH failure, got nil")
	}
	if res.Success {
		t.Fatal("expected Success=false after AUTH failure")
	}
	if res.StatusCode <= 0 {
		t.Fatalf("expected StatusCode > 0, got %d", res.StatusCode)
	}
	if res.Message == "" {
		t.Fatal("expected Message to be populated from SMTP error, got empty")
	}

	// Verify the error wraps an SMTPError.
	var smtpErr *esmtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("expected wrapped SMTPError, got: %T %v", err, err)
	}
}
