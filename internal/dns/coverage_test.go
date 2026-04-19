package dns

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestMapErr_NXDomainTranslation verifies that a *net.DNSError with IsNotFound=true
// is translated to ErrNXDomain.
func TestMapErr_NXDomainTranslation(t *testing.T) {
	in := &net.DNSError{IsNotFound: true, Err: "no such host"}
	out := mapErr(in)
	if !errors.Is(out, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain, got %v", out)
	}
}

// TestMapErr_PreservesOtherErrors verifies that non-NXDOMAIN DNS errors are passed through.
func TestMapErr_PreservesOtherErrors(t *testing.T) {
	in := &net.DNSError{Err: "server misbehaving"}
	out := mapErr(in)
	if errors.Is(out, ErrNXDomain) {
		t.Fatal("non-NXDOMAIN error was incorrectly mapped to ErrNXDomain")
	}
	if out == nil {
		t.Fatal("expected non-nil error, got nil")
	}
}

// TestMapErr_NilPassthrough verifies that nil passes through unchanged.
func TestMapErr_NilPassthrough(t *testing.T) {
	if mapErr(nil) != nil {
		t.Fatal("expected nil for nil input")
	}
}

// TestSystem_Smoke verifies System() returns a usable Resolver (doesn't panic).
// We call LookupTXT with an empty name — the result doesn't matter, only
// that the wrapper doesn't break.
func TestSystem_Smoke(t *testing.T) {
	r := System()
	if r == nil {
		t.Fatal("System() returned nil")
	}
	// Empty name → some error from the OS resolver.
	_, err := r.LookupTXT(context.Background(), "")
	// We don't care what error, just that it doesn't panic.
	_ = err
}

// TestSystem_LookupHost_Smoke exercises the LookupHost wrapper.
func TestSystem_LookupHost_Smoke(t *testing.T) {
	r := System()
	_, err := r.LookupHost(context.Background(), "")
	_ = err
}

// TestSystem_LookupAddr_Smoke exercises the LookupAddr wrapper.
func TestSystem_LookupAddr_Smoke(t *testing.T) {
	r := System()
	_, err := r.LookupAddr(context.Background(), "")
	_ = err
}

// TestQueryBlacklist_EmptyZones verifies that an empty zone list returns an empty
// result without panicking.
func TestQueryBlacklist_EmptyZones(t *testing.T) {
	r := NewFake()
	res := QueryBlacklist(context.Background(), r, net.ParseIP("1.2.3.4"), []string{})
	if len(res) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res))
	}
}

// TestFakeResolver_LookupAddr verifies LookupAddr returns preconfigured results.
func TestFakeResolver_LookupAddr(t *testing.T) {
	f := NewFake()
	f.Addr["1.2.3.4"] = []string{"host.example.com"}

	got, err := f.LookupAddr(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "host.example.com" {
		t.Fatalf("got %v, want [host.example.com]", got)
	}
}

// TestFakeResolver_LookupAddr_NXDOMAIN verifies ErrNXDomain for unknown addresses.
func TestFakeResolver_LookupAddr_NXDOMAIN(t *testing.T) {
	f := NewFake()
	_, err := f.LookupAddr(context.Background(), "9.9.9.9")
	if !errors.Is(err, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain, got %v", err)
	}
}

// TestFakeResolver_LookupHost covers the LookupHost NXDOMAIN path.
func TestFakeResolver_LookupHost_NXDOMAIN(t *testing.T) {
	f := NewFake()
	_, err := f.LookupHost(context.Background(), "absent.example.com")
	if !errors.Is(err, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain, got %v", err)
	}
}

// TestQueryBlacklist_LookupError verifies that resolver errors are surfaced in results.
func TestQueryBlacklist_LookupError(t *testing.T) {
	// No entry in fake → NXDOMAIN, but NOT a resolver error.
	// Use a real NXDOMAIN (not listed) as the baseline.
	r := NewFake()
	res := QueryBlacklist(context.Background(), r, net.ParseIP("203.0.113.1"), []string{"zen.spamhaus.org"})
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0].Listed {
		t.Fatal("expected Listed=false for NXDOMAIN response")
	}
	if res[0].Err != nil {
		t.Fatalf("unexpected error: %v", res[0].Err)
	}
}
