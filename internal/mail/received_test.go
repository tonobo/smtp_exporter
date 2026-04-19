package mail

import (
	"os"
	"testing"
)

func TestLastReceivingHost_Stalwart(t *testing.T) {
	received := []string{"from sender by mx.forststack.de (Stalwart) for <foo@bar>; Mon, 1 Jan 2024 00:00:00 +0000"}
	host, ok := LastReceivingHost(received)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if host != "mx.forststack.de" {
		t.Errorf("host = %q, want mx.forststack.de", host)
	}
}

func TestLastReceivingHost_Postfix(t *testing.T) {
	received := []string{"from x by mx2.example.com (Postfix) with ESMTPS id ABC; Mon, 1 Jan 2024 00:00:00 +0000"}
	host, ok := LastReceivingHost(received)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if host != "mx2.example.com" {
		t.Errorf("host = %q, want mx2.example.com", host)
	}
}

func TestLastReceivingHost_Empty(t *testing.T) {
	_, ok := LastReceivingHost(nil)
	if ok {
		t.Fatal("expected ok=false for empty slice")
	}
	_, ok = LastReceivingHost([]string{})
	if ok {
		t.Fatal("expected ok=false for empty slice")
	}
}

func TestLastReceivingHost_NoBy(t *testing.T) {
	received := []string{"from sender (EHLO example.com) [1.2.3.4] at Mon, 1 Jan 2024 00:00:00 +0000"}
	_, ok := LastReceivingHost(received)
	if ok {
		t.Fatal("expected ok=false when no 'by' clause present")
	}
}

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
