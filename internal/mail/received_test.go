package mail

import (
	"bytes"
	"net/mail"
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

func TestLastReceivingHost_BracketedIPv4(t *testing.T) {
	rcv := []string{`from x by [192.0.2.1] (Postfix) with ESMTPS id ABC123; Mon, 01 Apr 2026 10:00:00 +0000`}
	h, ok := LastReceivingHost(rcv)
	if !ok || h != "192.0.2.1" {
		t.Fatalf("got %q ok=%v", h, ok)
	}
}

func TestLastReceivingHost_BracketedIPv6(t *testing.T) {
	rcv := []string{`from x by [IPv6:2001:db8::1] with ESMTPS id ABC; Mon, 01 Apr 2026 10:00:00 +0000`}
	h, ok := LastReceivingHost(rcv)
	if !ok || h != "2001:db8::1" {
		t.Fatalf("got %q ok=%v", h, ok)
	}
}

func TestLastReceivingHost_GmailIPv6_Rejected(t *testing.T) {
	// Real Gmail Received form: "by 2002:a05:6022:1106:b0:23::: with SMTP id ..."
	// Without brackets the regex match would stop at the colon and return "2002".
	// We reject all-digit tokens to avoid emitting that garbage.
	rcv := []string{`by 2002:a05:6022:1106:b0:23:1234:5678 with SMTP id abc123; Mon, 01 Apr 2026 10:00:00 +0000`}
	h, ok := LastReceivingHost(rcv)
	if ok {
		t.Fatalf("expected reject, got %q", h)
	}
}

func TestLastReceivingHost_DovecotShortName(t *testing.T) {
	// mail.de uses internal short names like "dovecot06" — not FQDN but a real
	// host identifier, has at least one letter so we keep it.
	rcv := []string{`from x by dovecot06 (Dovecot) with LMTP id ABC; Mon, 01 Apr 2026 10:00:00 +0000`}
	h, ok := LastReceivingHost(rcv)
	if !ok || h != "dovecot06" {
		t.Fatalf("got %q ok=%v", h, ok)
	}
}

func parseReceivedHeaders(t *testing.T, raw []byte) []string {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return msg.Header["Received"]
}

func TestFirstPublicSenderIP_Simple(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/received_chains/simple.eml")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	received := parseReceivedHeaders(t, raw)
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
	received := parseReceivedHeaders(t, raw)
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
	received := parseReceivedHeaders(t, raw)
	ip, ok := FirstPublicSenderIP(received)
	if !ok || ip.String() != "2001:db8::1" {
		t.Fatalf("got %v ok=%v", ip, ok)
	}
}
