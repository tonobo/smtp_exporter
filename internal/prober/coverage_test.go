package prober

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

// TestRun_SMTPFailureEarlyReturn verifies that when SMTP send fails, the probe
// returns false and never sets probe_imap_message_received.
func TestRun_SMTPFailureEarlyReturn(t *testing.T) {
	// Find a closed port for SMTP.
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; finding a free port
	if err != nil {
		t.Fatal(err)
	}
	smtpAddr := l.Addr().String()
	_ = l.Close()

	mod := config.Module{
		Prober:  "mailflow",
		Timeout: 3 * time.Second,
		SMTP: config.SMTP{
			Server:   smtpAddr,
			TLS:      "no",
			EHLO:     "test",
			MailFrom: "probe@example.org",
			MailTo:   "target@other",
		},
		IMAP: config.IMAP{
			Server:       "127.0.0.1:1", // closed port — must never be reached
			TLS:          "no",
			Mailbox:      "INBOX",
			PollInterval: 200 * time.Millisecond,
			Auth:         config.Auth{Username: "u", Password: "p"},
		},
	}
	glb := config.Global{}

	reg := prometheus.NewRegistry()
	logger := slog.New(slog.DiscardHandler)
	ok := Run(context.Background(), logger, mod, "smtp_fail_test", glb, pdns.NewFake(), reg)
	if ok {
		t.Fatal("expected probe to fail when SMTP server is unreachable")
	}

	// probe_smtp_send_success must be 0
	assertGauge(t, reg, "probe_smtp_send_success", 0)

	// probe_imap_message_received must be 0 (default) since IMAP phase never ran.
	// It is registered but should have its zero default value (not set to 1).
	assertGauge(t, reg, "probe_imap_message_received", 0)
}

// TestClassifyFolder covers all folder classification branches.
func TestClassifyFolder(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"INBOX", "inbox"},
		{"[Gmail]/Spam", "spam"},
		{"Junk", "junk"},
		{"Sent", "other"},
		{"spam-folder", "spam"},
		{"my-junk-mail", "junk"},
	}
	for _, tc := range cases {
		got := classifyFolder(tc.in)
		if got != tc.want {
			t.Errorf("classifyFolder(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRun_InvalidSMTPTLSConfig verifies that a bad SMTP TLS ca_file causes early failure.
func TestRun_InvalidSMTPTLSConfig(t *testing.T) {
	dir := t.TempDir()
	// An empty file is a valid path but has no certs — BuildTLSConfig will error.
	caPath := dir + "/ca.pem"
	if err := os.WriteFile(caPath, []byte("not a pem"), 0600); err != nil {
		t.Fatal(err)
	}

	mod := config.Module{
		Prober:  "mailflow",
		Timeout: 3 * time.Second,
		SMTP: config.SMTP{
			Server:   "127.0.0.1:1",
			TLS:      "starttls",
			MailFrom: "probe@example.org",
			MailTo:   "target@other",
			TLSConfig: config.TLSConfig{
				CAFile: caPath,
			},
		},
		IMAP: config.IMAP{
			Server:       "127.0.0.1:1",
			TLS:          "tls",
			Mailbox:      "INBOX",
			PollInterval: 200 * time.Millisecond,
		},
	}
	glb := config.Global{}

	reg := prometheus.NewRegistry()
	logger := slog.New(slog.DiscardHandler)
	ok := Run(context.Background(), logger, mod, "bad_smtp_tls_test", glb, pdns.NewFake(), reg)
	if ok {
		t.Fatal("expected probe to fail with invalid SMTP TLS config")
	}
}

// TestRun_InvalidIMAPTLSConfig verifies that a bad IMAP TLS ca_file causes failure.
func TestRun_InvalidIMAPTLSConfig(t *testing.T) {
	dir := t.TempDir()
	caPath := dir + "/bad-ca.pem"
	if err := os.WriteFile(caPath, []byte("not a pem"), 0600); err != nil {
		t.Fatal(err)
	}

	mod := config.Module{
		Prober:  "mailflow",
		Timeout: 3 * time.Second,
		SMTP: config.SMTP{
			Server:   "127.0.0.1:1",
			TLS:      "no",
			MailFrom: "probe@example.org",
			MailTo:   "target@other",
		},
		IMAP: config.IMAP{
			Server:       "127.0.0.1:1",
			TLS:          "tls",
			Mailbox:      "INBOX",
			PollInterval: 200 * time.Millisecond,
			TLSConfig: config.TLSConfig{
				CAFile: caPath,
			},
		},
	}
	glb := config.Global{}

	reg := prometheus.NewRegistry()
	logger := slog.New(slog.DiscardHandler)
	ok := Run(context.Background(), logger, mod, "bad_imap_tls_test", glb, pdns.NewFake(), reg)
	if ok {
		t.Fatal("expected probe to fail with invalid IMAP TLS config")
	}
}
