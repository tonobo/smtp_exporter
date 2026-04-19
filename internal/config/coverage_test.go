package config

import (
	"crypto/tls"
	"os"
	"sync"
	"testing"
)

// TestEnsureTLSMin_NilReturnsNil verifies nil passthrough.
func TestEnsureTLSMin_NilReturnsNil(t *testing.T) {
	if EnsureTLSMin(nil) != nil {
		t.Fatal("expected nil for nil input")
	}
}

// TestEnsureTLSMin_PreservesExistingMinVersion verifies that a config with
// MinVersion already set is returned unchanged (same pointer, same version).
func TestEnsureTLSMin_PreservesExistingMinVersion(t *testing.T) {
	in := &tls.Config{MinVersion: tls.VersionTLS13}
	out := EnsureTLSMin(in)
	if out != in {
		t.Fatal("expected same pointer when MinVersion already set")
	}
	if out.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion changed: %d", out.MinVersion)
	}
}

// TestEnsureTLSMin_ClonesWhenSettingMin verifies that a config with MinVersion=0
// is cloned and the clone gets MinVersion=TLS12. Mutating original must not affect clone.
func TestEnsureTLSMin_ClonesWhenSettingMin(t *testing.T) {
	in := &tls.Config{MinVersion: 0, ServerName: "example.com"}
	out := EnsureTLSMin(in)
	if out == in {
		t.Fatal("expected a clone (different pointer) when MinVersion was 0")
	}
	if out.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want %d", out.MinVersion, tls.VersionTLS12)
	}
	// Mutating the original must not affect the clone.
	in.ServerName = "mutated"
	if out.ServerName != "example.com" {
		t.Fatal("clone was affected by mutation of original")
	}
}

// TestHostOnly covers the HostOnly helper.
func TestHostOnly(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"host:port", "host"},
		{"host:", "host"},
		{"host", "host"},
		{"[::1]:25", "::1"},
		{"mail.example.com:587", "mail.example.com"},
	}
	for _, tc := range cases {
		got := HostOnly(tc.in)
		if got != tc.want {
			t.Errorf("HostOnly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSafeConfig_RaceReadersVsReload runs concurrent readers + reloads.
// Run with -race to detect data races.
func TestSafeConfig_RaceReadersVsReload(t *testing.T) {
	// Write a minimal valid config to a temp file.
	const cfgYAML = `
modules:
  example:
    prober: mailflow
    timeout: 30s
    smtp:
      server: mail.example.org:587
      tls: starttls
      mail_from: probe@example.org
      mail_to: target@example.com
    imap:
      server: imap.example.com:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s
`
	dir := t.TempDir()
	path := dir + "/cfg.yaml"
	if err := os.WriteFile(path, []byte(cfgYAML), 0600); err != nil {
		t.Fatal(err)
	}

	sc := NewSafeConfig()
	if err := sc.Reload(path); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	// 10 readers × 100 reads each
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = sc.Get()
			}
		}()
	}
	// 10 concurrent reloads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				_ = sc.Reload(path)
			}
		}()
	}
	wg.Wait()
}

// TestValidate_MissingProbeFields verifies that missing smtp/imap required
// fields produce appropriate errors.
func TestValidate_MissingProbeFields(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "missing smtp server",
			yaml: `modules:
  x:
    prober: mailflow
    timeout: 30s
    smtp:
      tls: starttls
      mail_from: a@b
      mail_to: c@d
    imap:
      server: imap:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s`,
		},
		{
			name: "missing mail_from",
			yaml: `modules:
  x:
    prober: mailflow
    timeout: 30s
    smtp:
      server: smtp:587
      tls: starttls
      mail_to: c@d
    imap:
      server: imap:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s`,
		},
		{
			name: "missing mail_to",
			yaml: `modules:
  x:
    prober: mailflow
    timeout: 30s
    smtp:
      server: smtp:587
      tls: starttls
      mail_from: a@b
    imap:
      server: imap:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s`,
		},
		{
			name: "missing imap server",
			yaml: `modules:
  x:
    prober: mailflow
    timeout: 30s
    smtp:
      server: smtp:587
      tls: starttls
      mail_from: a@b
      mail_to: c@d
    imap:
      tls: tls
      mailbox: INBOX
      poll_interval: 2s`,
		},
		{
			name: "missing imap mailbox",
			yaml: `modules:
  x:
    prober: mailflow
    timeout: 30s
    smtp:
      server: smtp:587
      tls: starttls
      mail_from: a@b
      mail_to: c@d
    imap:
      server: imap:993
      tls: tls
      poll_interval: 2s`,
		},
		{
			name: "zero timeout",
			yaml: `modules:
  x:
    prober: mailflow
    timeout: 0
    smtp:
      server: smtp:587
      tls: starttls
      mail_from: a@b
      mail_to: c@d
    imap:
      server: imap:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s`,
		},
		{
			name: "unknown prober",
			yaml: `modules:
  x:
    prober: unknown
    timeout: 30s
    smtp:
      server: smtp:587
      tls: starttls
      mail_from: a@b
      mail_to: c@d
    imap:
      server: imap:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s`,
		},
		{
			name: "no modules",
			yaml: `modules: {}`,
		},
		{
			name: "cleanup enabled without max_age",
			yaml: `global:
  cleanup:
    enabled: true
    max_age: 0
modules:
  x:
    prober: mailflow
    timeout: 30s
    smtp:
      server: smtp:587
      tls: starttls
      mail_from: a@b
      mail_to: c@d
    imap:
      server: imap:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := dir + "/cfg.yaml"
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
		})
	}
}
