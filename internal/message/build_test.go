package message

import (
	"net/mail"
	"strings"
	"testing"
)

func TestBuild_HasAutoSubmittedHeader(t *testing.T) {
	got := Build(Input{
		ProbeID:  "22222222-2222-2222-2222-222222222222",
		From:     "probe@forststack.de",
		To:       "forststack@gmail.com",
		Hostname: "exporter.example",
	})

	if !strings.Contains(got.RFC5322, "Auto-Submitted: auto-generated\r\n") {
		t.Fatalf("missing Auto-Submitted header in:\n%s", got.RFC5322)
	}

	// Verify it also parses cleanly via net/mail.
	msg, err := mail.ReadMessage(strings.NewReader(got.RFC5322))
	if err != nil {
		t.Fatalf("parse rfc5322: %v", err)
	}
	if got := msg.Header.Get("Auto-Submitted"); got != "auto-generated" {
		t.Fatalf("Auto-Submitted = %q, want auto-generated", got)
	}
}

func TestBuild_HeadersAndID(t *testing.T) {
	got := Build(Input{
		ProbeID:  "11111111-1111-1111-1111-111111111111",
		From:     "probe@example.org",
		To:       "target@other.example",
		Hostname: "exporter.example",
	})

	if !strings.HasPrefix(got.Subject, "[smtp_exporter] ") {
		t.Fatalf("subject: %q", got.Subject)
	}
	if !strings.Contains(got.Subject, got.ProbeID) {
		t.Fatalf("subject missing probe id: %q", got.Subject)
	}

	msg, err := mail.ReadMessage(strings.NewReader(got.RFC5322))
	if err != nil {
		t.Fatalf("parse rfc5322: %v", err)
	}
	if msg.Header.Get("X-Probe-ID") != got.ProbeID {
		t.Fatalf("x-probe-id: %q", msg.Header.Get("X-Probe-ID"))
	}
	if !strings.Contains(msg.Header.Get("Message-ID"), got.ProbeID) {
		t.Fatalf("message-id: %q", msg.Header.Get("Message-ID"))
	}
	if msg.Header.Get("From") != "probe@example.org" {
		t.Fatalf("from: %q", msg.Header.Get("From"))
	}
	if msg.Header.Get("Date") == "" {
		t.Fatal("missing Date")
	}
}
