package mail

import (
	"os"
	"testing"
)

func TestFirstPublicSenderIP_Simple(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/received_chains/simple.eml")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	received := ParseReceivedHeaders(raw)
	ip, ok := FirstPublicSenderIP(received)
	if !ok || ip.String() != "198.51.100.7" {
		t.Fatalf("got %v ok=%v", ip, ok)
	}
}

func TestFirstPublicSenderIP_MultiHopSkipsPrivate(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/received_chains/multi-hop.eml")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	received := ParseReceivedHeaders(raw)
	ip, ok := FirstPublicSenderIP(received)
	if !ok || ip.String() != "203.0.113.9" {
		t.Fatalf("got %v ok=%v", ip, ok)
	}
}

func TestFirstPublicSenderIP_IPv6(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/received_chains/ipv6.eml")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	received := ParseReceivedHeaders(raw)
	ip, ok := FirstPublicSenderIP(received)
	if !ok || ip.String() != "2001:db8::1" {
		t.Fatalf("got %v ok=%v", ip, ok)
	}
}
