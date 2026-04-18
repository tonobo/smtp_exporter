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

func TestBuild_HasAutoResponseSuppressHeader(t *testing.T) {
	got := Build(Input{ProbeID: "abc", From: "a@b.c", To: "x@y.z", Hostname: "h", ModuleName: "example"})
	if !strings.Contains(got.RFC5322, "\r\nX-Auto-Response-Suppress: All\r\n") {
		t.Fatalf("missing X-Auto-Response-Suppress header in:\n%s", got.RFC5322)
	}
}

func TestBuild_HasUserAgentHeader(t *testing.T) {
	got := Build(Input{ProbeID: "abc", From: "a@b.c", To: "x@y.z", Hostname: "h", ModuleName: "example"})
	if !strings.Contains(got.RFC5322, "User-Agent: smtp_exporter/") {
		t.Fatalf("missing User-Agent header in:\n%s", got.RFC5322)
	}
	if !strings.Contains(got.RFC5322, "(+https://github.com/tonobo/smtp_exporter)") {
		t.Fatalf("User-Agent missing repo URL in:\n%s", got.RFC5322)
	}
}

func TestBuild_HasFeedbackID(t *testing.T) {
	got := Build(Input{ProbeID: "abc", From: "probe@example.org", To: "x@y.z", Hostname: "h", ModuleName: "stalwart_to_gmail"})
	if !strings.Contains(got.RFC5322, "Feedback-ID: probe:example.org:stalwart_to_gmail:smtp_exporter") {
		t.Fatalf("missing/wrong Feedback-ID in:\n%s", got.RFC5322)
	}
}

func TestBuild_MessageIDUsesFromDomain(t *testing.T) {
	got := Build(Input{
		ProbeID: "abc", From: "probe@example.org",
		To: "x@y.z", Hostname: "some-pod-name-12345",
		ModuleName: "example",
	})
	// Message-ID domain must be example.org, NOT some-pod-name-12345
	if !strings.Contains(got.RFC5322, "Message-ID: <abc@example.org>") {
		t.Fatalf("message-id domain wrong: %q", got.RFC5322)
	}
}

func TestBuild_ReputationHeadersPresent(t *testing.T) {
	got := Build(Input{
		ProbeID: "abc", From: "probe@example.org",
		To: "x@y.z", Hostname: "h", ModuleName: "stalwart_to_gmail",
	})
	wantSubstrings := []string{
		"Auto-Submitted: auto-generated\r\n",
		"X-Auto-Response-Suppress: All\r\n",
		"User-Agent: smtp_exporter/",
		"(+https://github.com/tonobo/smtp_exporter)",
		"Feedback-ID: probe:example.org:stalwart_to_gmail:smtp_exporter\r\n",
		"MT-Priority: -4 (NON-URGENT)\r\n",
		"Importance: Low\r\n",
		"X-Priority: 5\r\n",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(got.RFC5322, s) {
			t.Errorf("missing %q in:\n%s", s, got.RFC5322)
		}
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
