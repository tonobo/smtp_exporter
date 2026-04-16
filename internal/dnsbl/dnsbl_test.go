package dnsbl

import (
	"context"
	"net"
	"testing"

	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

func TestQuery_Listed(t *testing.T) {
	r := pdns.NewFake()
	r.Host["7.100.51.198.zen.spamhaus.org"] = []string{"127.0.0.2"}

	ctx := context.Background()
	res := Query(ctx, r, net.ParseIP("198.51.100.7"), []string{"zen.spamhaus.org"})

	if len(res) != 1 {
		t.Fatalf("results: %d", len(res))
	}
	if !res[0].Listed || res[0].Zone != "zen.spamhaus.org" {
		t.Fatalf("%#v", res[0])
	}
}

func TestQuery_NotListed(t *testing.T) {
	r := pdns.NewFake()
	// no entry → NXDOMAIN
	res := Query(context.Background(), r, net.ParseIP("203.0.113.9"), []string{"bl.spamcop.net"})
	if len(res) != 1 || res[0].Listed {
		t.Fatalf("%#v", res)
	}
}

func TestReverseIPv4(t *testing.T) {
	got := reverseIP(net.ParseIP("1.2.3.4"))
	if got != "4.3.2.1" {
		t.Fatalf("%q", got)
	}
}

func TestReverseIPv6(t *testing.T) {
	got := reverseIP(net.ParseIP("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
	if got != want {
		t.Fatalf("%q", got)
	}
}
