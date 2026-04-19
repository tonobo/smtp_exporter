package dns

import (
	"context"
	"net"
	"testing"
)

func TestQueryBlacklist_Listed(t *testing.T) {
	r := NewFake()
	r.Host["7.100.51.198.zen.spamhaus.org"] = []string{"127.0.0.2"}

	ctx := context.Background()
	res := QueryBlacklist(ctx, r, net.ParseIP("198.51.100.7"), []string{"zen.spamhaus.org"})

	if len(res) != 1 {
		t.Fatalf("results: %d", len(res))
	}
	if !res[0].Listed || res[0].Zone != "zen.spamhaus.org" {
		t.Fatalf("%#v", res[0])
	}
	if res[0].ResponseCode != "127.0.0.2" {
		t.Fatalf("ResponseCode: %q, want 127.0.0.2", res[0].ResponseCode)
	}
}

func TestQueryBlacklist_NotListed(t *testing.T) {
	r := NewFake()
	// no entry → NXDOMAIN
	res := QueryBlacklist(context.Background(), r, net.ParseIP("203.0.113.9"), []string{"bl.spamcop.net"})
	if len(res) != 1 || res[0].Listed {
		t.Fatalf("%#v", res)
	}
	if res[0].ResponseCode != "" {
		t.Fatalf("ResponseCode on NXDOMAIN: %q, want empty", res[0].ResponseCode)
	}
}

// TestQueryBlacklist_RateLimitCodes covers Spamhaus return codes that indicate
// open-resolver refusal, rate-limiting, or typing errors. These are
// NOT listings — a clean IP querying from a throttled resolver must
// not be reported as listed.
//
// Reference:
// https://www.spamhaus.org/blocklists/dnsbl-usage/return-codes/
func TestQueryBlacklist_RateLimitCodes(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"rate-limit", "127.255.255.254"},
		{"excessive-queries", "127.255.255.255"},
		{"typing-error", "127.255.255.252"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewFake()
			r.Host["7.100.51.198.zen.spamhaus.org"] = []string{tc.code}

			res := QueryBlacklist(context.Background(), r, net.ParseIP("198.51.100.7"), []string{"zen.spamhaus.org"})
			if len(res) != 1 {
				t.Fatalf("results: %d", len(res))
			}
			if res[0].Listed {
				t.Fatalf("Listed=true for rate-limit code %s (should be false)", tc.code)
			}
			if res[0].ResponseCode != tc.code {
				t.Fatalf("ResponseCode=%q, want %q", res[0].ResponseCode, tc.code)
			}
		})
	}
}

// TestQueryBlacklist_ListingRangeBoundaries covers the inclusive boundaries of
// the real-listing range (127.0.0.2..127.0.0.11) and the off-by-one
// neighbours that must NOT count as listed.
func TestQueryBlacklist_ListingRangeBoundaries(t *testing.T) {
	cases := []struct {
		name       string
		code       string
		wantListed bool
	}{
		{"127.0.0.1-reserved", "127.0.0.1", false},
		{"127.0.0.2-sbl", "127.0.0.2", true},
		{"127.0.0.3-css", "127.0.0.3", true},
		{"127.0.0.4-xbl-cbl", "127.0.0.4", true},
		{"127.0.0.9-sbl-dbl", "127.0.0.9", true},
		{"127.0.0.10-pbl-isp", "127.0.0.10", true},
		{"127.0.0.11-pbl-spamhaus", "127.0.0.11", true},
		{"127.0.0.12-out-of-range", "127.0.0.12", false},
		{"127.0.1.2-wrong-third-octet", "127.0.1.2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewFake()
			r.Host["7.100.51.198.zen.spamhaus.org"] = []string{tc.code}

			res := QueryBlacklist(context.Background(), r, net.ParseIP("198.51.100.7"), []string{"zen.spamhaus.org"})
			if len(res) != 1 {
				t.Fatalf("results: %d", len(res))
			}
			if res[0].Listed != tc.wantListed {
				t.Fatalf("Listed=%v for code %s, want %v", res[0].Listed, tc.code, tc.wantListed)
			}
			if res[0].ResponseCode != tc.code {
				t.Fatalf("ResponseCode=%q, want %q", res[0].ResponseCode, tc.code)
			}
		})
	}
}

// TestQueryBlacklist_InvalidIP verifies that an IP with an unexpected length
// (neither 4-byte IPv4 nor 16-byte IPv6) returns nil without panicking or
// making any DNS queries.
func TestQueryBlacklist_InvalidIP(t *testing.T) {
	r := NewFake()
	// net.IP of length 1 is neither IPv4 (4) nor IPv6 (16).
	badIP := net.IP{0x00}
	res := QueryBlacklist(context.Background(), r, badIP, []string{"zen.spamhaus.org"})
	if res != nil {
		t.Fatalf("expected nil result for invalid IP, got %v", res)
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
