package dns

import (
	"context"
	"errors"
	"testing"
)

func TestFake_LookupTXT(t *testing.T) {
	f := NewFake()
	f.TXT["example.com"] = []string{"v=spf1 -all"}

	got, err := f.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "v=spf1 -all" {
		t.Fatalf("got %v", got)
	}
}

func TestFake_LookupTXT_NXDOMAIN(t *testing.T) {
	f := NewFake()
	_, err := f.LookupTXT(context.Background(), "absent.example.com")
	if !errors.Is(err, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain, got %v", err)
	}
}
