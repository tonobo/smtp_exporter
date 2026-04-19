package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	esmtp "github.com/emersion/go-smtp"

	"github.com/tonobo/smtp_exporter/internal/testutil/smtpfake"
	"github.com/tonobo/smtp_exporter/internal/testutil/tlstest"
)

// TestSend_DirectTLS verifies Send works with TLS:"tls" (implicit TLS).
func TestSend_DirectTLS(t *testing.T) {
	_, serverCfg, clientCfg := tlstest.SelfSigned(t)
	fake := smtpfake.StartDirectTLS(t, smtpfake.Backend{}, serverCfg)

	in := Input{
		Server:    fake.Addr,
		TLS:       "tls",
		EHLO:      "client.local",
		MailFrom:  "probe@example.org",
		MailTo:    "target@other.example",
		Data:      []byte("Subject: tls-direct\r\n\r\nhi\r\n"),
		TLSConfig: clientCfg,
	}
	res, err := Send(context.Background(), in)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got code=%d msg=%q", res.StatusCode, res.Message)
	}
	if !res.UsedTLS {
		t.Fatal("expected UsedTLS=true")
	}
}

// TestSend_StartTLS_FailNoTLSSupport verifies that requesting STARTTLS to a
// plain server returns an appropriate error.
func TestSend_StartTLS_FailNoTLSSupport(t *testing.T) {
	// Plain server with no TLS config.
	fake := smtpfake.Start(t, smtpfake.Backend{})

	in := Input{
		Server:   fake.Addr,
		TLS:      "starttls",
		MailFrom: "probe@example.org",
		MailTo:   "target@other.example",
		Data:     []byte("Subject: test\r\n\r\nhi\r\n"),
		// clientTLS that doesn't trust anything → STARTTLS will fail
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost"},
	}
	_, err := Send(context.Background(), in)
	if err == nil {
		t.Fatal("expected error when STARTTLS fails, got nil")
	}
}

// TestSend_AuthFailure_Detailed verifies that auth failure populates Result.
func TestSend_AuthFailure_Detailed(t *testing.T) {
	fake := smtpfake.Start(t, smtpfake.Backend{
		OnAuth: func(_, _ string) error {
			return &esmtp.SMTPError{Code: 535, Message: "5.7.8 Authentication credentials invalid"}
		},
	})

	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		EHLO:     "client.local",
		Username: "user@example.org",
		Password: "wrongpassword",
		MailFrom: "probe@example.org",
		MailTo:   "target@other.example",
		Data:     []byte("Subject: auth-fail\r\n\r\nhi\r\n"),
	}
	res, err := Send(context.Background(), in)
	if err == nil {
		t.Fatal("expected error from AUTH failure, got nil")
	}
	if res.Success {
		t.Fatal("expected Success=false")
	}
	if res.StatusCode <= 0 {
		t.Fatalf("expected StatusCode > 0, got %d", res.StatusCode)
	}
	if res.Message == "" {
		t.Fatal("expected Message to be populated")
	}
}

// TestSend_RcptRefused verifies that RCPT failure populates Result.
func TestSend_RcptRefused(t *testing.T) {
	fake := smtpfake.Start(t, smtpfake.Backend{
		OnRcpt: func(_ string) error {
			return &esmtp.SMTPError{Code: 550, Message: "5.1.1 User unknown"}
		},
	})

	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		EHLO:     "client.local",
		MailFrom: "probe@example.org",
		MailTo:   "unknown@other.example",
		Data:     []byte("Subject: rcpt-fail\r\n\r\nhi\r\n"),
	}
	res, err := Send(context.Background(), in)
	if err == nil {
		t.Fatal("expected error from RCPT failure, got nil")
	}
	if res.Success {
		t.Fatal("expected Success=false")
	}
	if res.StatusCode <= 0 {
		t.Fatalf("expected StatusCode > 0, got %d", res.StatusCode)
	}
}

// TestSend_DataFailure verifies that DATA failure populates Result.
func TestSend_DataFailure(t *testing.T) {
	fake := smtpfake.Start(t, smtpfake.Backend{
		OnData: func(_ []byte) error {
			return &esmtp.SMTPError{Code: 552, Message: "5.3.4 Message too large"}
		},
	})

	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		EHLO:     "client.local",
		MailFrom: "probe@example.org",
		MailTo:   "target@other.example",
		Data:     bytes.Repeat([]byte("X"), 100),
	}
	res, err := Send(context.Background(), in)
	if err == nil {
		t.Fatal("expected error from DATA failure, got nil")
	}
	if res.Success {
		t.Fatal("expected Success=false")
	}
}

// TestTLSVersionName_AllCases table-tests all 5 cases.
func TestTLSVersionName_AllCases(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
		{0x9999, "unknown"},
	}
	for _, tc := range cases {
		got := tlsVersionName(tc.v)
		if got != tc.want {
			t.Errorf("tlsVersionName(%04x) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// TestDial_InvalidTLSMode verifies dial returns an error for unknown TLS mode.
func TestDial_InvalidTLSMode(t *testing.T) {
	in := Input{
		Server: "127.0.0.1:1",
		TLS:    "bogus",
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := dial(ctx, in)
	if err == nil {
		t.Fatal("expected error for invalid TLS mode")
	}
}

// TestDial_NoTLS_ClosedPort verifies that a closed port returns a connection error.
func TestDial_NoTLS_ClosedPort(t *testing.T) {
	// Find a port that's definitely closed.
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; finding a free port
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	in := Input{Server: addr, TLS: "no"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dial(ctx, in)
	if err == nil {
		t.Fatal("expected error dialing closed port")
	}
}

// TestSend_MailFromRefused verifies that MAIL FROM failure populates Result.
func TestSend_MailFromRefused(t *testing.T) {
	fake := smtpfake.Start(t, smtpfake.Backend{
		OnMail: func(_ string) error {
			return &esmtp.SMTPError{Code: 553, Message: "5.1.3 Invalid sender address"}
		},
	})

	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		EHLO:     "client.local",
		MailFrom: "invalid@",
		MailTo:   "target@other.example",
		Data:     []byte("Subject: test\r\n\r\nhi\r\n"),
	}
	res, err := Send(context.Background(), in)
	if err == nil {
		t.Fatal("expected error from MAIL FROM failure, got nil")
	}
	if res.Success {
		t.Fatal("expected Success=false")
	}
}

// Ensure errors package is used.
var _ = errors.New
