package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_Minimal(t *testing.T) {
	c, err := Load("../../testdata/config/minimal.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Modules) != 1 {
		t.Fatalf("modules: %d", len(c.Modules))
	}
	m := c.Modules["example"]
	if m.Prober != "mailflow" {
		t.Fatalf("prober: %q", m.Prober)
	}
	if m.Timeout != 180*time.Second {
		t.Fatalf("timeout: %v", m.Timeout)
	}
	if m.SMTP.TLS != "starttls" {
		t.Fatalf("smtp.tls: %q", m.SMTP.TLS)
	}
	if len(c.Global.DNSBL.Zones) != 2 {
		t.Fatalf("dnsbl zones: %d", len(c.Global.DNSBL.Zones))
	}
}

func TestLoad_InvalidTLS(t *testing.T) {
	_, err := Load("../../testdata/config/invalid-tls.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoad_MoveFromSpam(t *testing.T) {
	cfg := `
global:
  cleanup:
    enabled: true
    max_age: 24h
    move_from_spam: true

modules:
  example:
    prober: mailflow
    timeout: 30s
    smtp:
      server: mail.example.org:587
      tls: starttls
      ehlo: mail.example.org
      mail_from: probe@example.org
      mail_to: target@example.com
    imap:
      server: imap.example.com:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s
`
	dir := t.TempDir()
	cfgPath := dir + "/cfg.yaml"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	c, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.Global.Cleanup.MoveFromSpam {
		t.Error("MoveFromSpam should be true")
	}
}

func TestLoad_ExpandsEnvVars(t *testing.T) {
	t.Setenv("TEST_SMTP_PASSWORD", "secret123")
	t.Setenv("TEST_IMAP_PASSWORD", "imap456")

	cfg := `
global:
  dnsbl:
    zones:
      - zen.spamhaus.org
  cleanup:
    enabled: true
    max_age: 24h

modules:
  example:
    prober: mailflow
    timeout: 30s
    smtp:
      server: mail.example.org:587
      tls: starttls
      ehlo: mail.example.org
      auth:
        username: probe@example.org
        password: ${TEST_SMTP_PASSWORD}
      mail_from: probe@example.org
      mail_to: target@other.example
    imap:
      server: imap.other.example:993
      tls: tls
      auth:
        username: target@other.example
        password: $TEST_IMAP_PASSWORD
      mailbox: INBOX
      poll_interval: 2s
`
	dir := t.TempDir()
	cfgPath := dir + "/cfg.yaml"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	c, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	m := c.Modules["example"]
	if m.SMTP.Auth.Password != "secret123" {
		t.Errorf("smtp.auth.password: got %q, want %q", m.SMTP.Auth.Password, "secret123")
	}
	if m.IMAP.Auth.Password != "imap456" {
		t.Errorf("imap.auth.password: got %q, want %q", m.IMAP.Auth.Password, "imap456")
	}
}
