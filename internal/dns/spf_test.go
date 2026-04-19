package dns

import (
	"context"
	"testing"
)

func TestLookupSPF_Present(t *testing.T) {
	r := NewFake()
	r.TXT["example.org"] = []string{"v=spf1 ip4:198.51.100.0/24 -all"}
	res := LookupSPF(context.Background(), r, "example.org")
	if !res.Found {
		t.Fatal("expected found")
	}
	if res.Record != "v=spf1 ip4:198.51.100.0/24 -all" {
		t.Fatalf("record=%q", res.Record)
	}
}

func TestLookupSPF_Missing(t *testing.T) {
	r := NewFake()
	res := LookupSPF(context.Background(), r, "missing.example.org")
	if res.Found {
		t.Fatal("expected not found")
	}
}

func TestLookupSPF_SkipsNonSPF(t *testing.T) {
	r := NewFake()
	r.TXT["example.org"] = []string{"some-other-txt", "v=spf1 -all"}
	res := LookupSPF(context.Background(), r, "example.org")
	if !res.Found || res.Record != "v=spf1 -all" {
		t.Fatalf("%#v", res)
	}
}

func TestLookupSPF_NXDOMAIN_NoError(t *testing.T) {
	r := NewFake()
	// key absent → ErrNXDomain from resolver
	res := LookupSPF(context.Background(), r, "gone.example.org")
	if res.Found {
		t.Fatal("expected not found")
	}
	if res.Err != nil {
		t.Fatalf("expected nil Err for NXDOMAIN, got %v", res.Err)
	}
}
