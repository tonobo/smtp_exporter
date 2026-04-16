package config

import (
	"testing"
)

func TestSafeConfig_ReloadSwap(t *testing.T) {
	s := NewSafeConfig()
	if err := s.Reload("../../testdata/config/minimal.yaml"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	c1 := s.Get()
	if _, ok := c1.Modules["stalwart_to_mail_de"]; !ok {
		t.Fatal("expected module after first load")
	}

	// Bad reload must not swap out the live config.
	if err := s.Reload("../../testdata/config/invalid-tls.yaml"); err == nil {
		t.Fatal("expected error from invalid config")
	}
	c2 := s.Get()
	if _, ok := c2.Modules["stalwart_to_mail_de"]; !ok {
		t.Fatal("live config should be unchanged after failed reload")
	}
}
