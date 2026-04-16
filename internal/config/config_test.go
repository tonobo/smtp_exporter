package config

import (
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
