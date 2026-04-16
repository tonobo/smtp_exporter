package spf

import (
	"context"
	"testing"

	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

func TestLookup_Present(t *testing.T) {
	r := pdns.NewFake()
	r.TXT["example.org"] = []string{"v=spf1 ip4:198.51.100.0/24 -all"}
	res := Lookup(context.Background(), r, "example.org")
	if !res.Found {
		t.Fatal("expected found")
	}
	if res.Record != "v=spf1 ip4:198.51.100.0/24 -all" {
		t.Fatalf("record=%q", res.Record)
	}
}

func TestLookup_Missing(t *testing.T) {
	r := pdns.NewFake()
	res := Lookup(context.Background(), r, "missing.example.org")
	if res.Found {
		t.Fatal("expected not found")
	}
}

func TestLookup_SkipsNonSPF(t *testing.T) {
	r := pdns.NewFake()
	r.TXT["example.org"] = []string{"some-other-txt", "v=spf1 -all"}
	res := Lookup(context.Background(), r, "example.org")
	if !res.Found || res.Record != "v=spf1 -all" {
		t.Fatalf("%#v", res)
	}
}
