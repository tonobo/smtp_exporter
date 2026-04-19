package mail

import (
	"net/mail"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestParseSpamHeaders_Malformed verifies that parsers handle empty/garbage values
// gracefully — no panic, no metric emitted for malformed data.
func TestParseSpamHeaders_Malformed(t *testing.T) {
	cases := []struct {
		name   string
		header mail.Header
	}{
		{
			name:   "empty X-Spam-Score",
			header: mail.Header{"X-Spam-Score": []string{""}},
		},
		{
			name:   "non-numeric X-Spam-Score",
			header: mail.Header{"X-Spam-Score": []string{"not-a-number"}},
		},
		{
			name:   "empty X-MS-Exchange-Organization-SCL",
			header: mail.Header{"X-MS-Exchange-Organization-SCL": []string{""}},
		},
		{
			name:   "non-numeric microsoft SCL",
			header: mail.Header{"X-MS-Exchange-Organization-SCL": []string{"bogus"}},
		},
		{
			name:   "empty X-Barracuda-Spam-Score",
			header: mail.Header{"X-Barracuda-Spam-Score": []string{""}},
		},
		{
			name:   "empty X-Mimecast-Spam-Score",
			header: mail.Header{"X-Mimecast-Spam-Score": []string{""}},
		},
		{
			name:   "non-numeric X-Mimecast-Spam-Score",
			header: mail.Header{"X-Mimecast-Spam-Score": []string{"bad"}},
		},
		{
			name:   "no spam headers at all",
			header: mail.Header{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m := NewSpamMetrics(reg)
			// Should not panic.
			m.ObserveSpam(tc.header)
		})
	}
}

// TestParseProofpoint verifies Proofpoint header detection.
func TestParseProofpoint(t *testing.T) {
	h := mail.Header{
		"X-Proofpoint-Spam-Details": []string{"rule=spam_level setting=high action=quarantine"},
	}
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := gaugeValue(t, reg, "probe_spam_flag", "source", "proofpoint"); got != 1 {
		t.Fatalf("proofpoint flag = %v, want 1", got)
	}
}

// TestParseMimecast verifies Mimecast score parsing.
func TestParseMimecast(t *testing.T) {
	h := mail.Header{"X-Mimecast-Spam-Score": []string{"3.5"}}
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := gaugeValue(t, reg, "probe_spam_score", "source", "mimecast"); got != 3.5 {
		t.Fatalf("mimecast score = %v, want 3.5", got)
	}
}

// TestParseSpamAssassin_StatusOnly verifies SpamAssassin detection from X-Spam-Status only.
func TestParseSpamAssassin_StatusOnly(t *testing.T) {
	h := mail.Header{"X-Spam-Status": []string{"Yes, score=8.7 required=5.0"}}
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := gaugeValue(t, reg, "probe_spam_flag", "source", "spamassassin"); got != 1 {
		t.Fatalf("flag = %v, want 1", got)
	}
	if got := gaugeValue(t, reg, "probe_spam_score", "source", "spamassassin"); got != 8.7 {
		t.Fatalf("score = %v, want 8.7", got)
	}
}

// TestParseSpamAssassin_Flag verifies X-Spam-Flag YES detection.
func TestParseSpamAssassin_Flag(t *testing.T) {
	h := mail.Header{"X-Spam-Flag": []string{"YES"}}
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := gaugeValue(t, reg, "probe_spam_flag", "source", "spamassassin"); got != 1 {
		t.Fatalf("flag = %v, want 1", got)
	}
}

// TestParseSpamAssassin_NoFlag verifies X-Spam-Flag NO detection.
func TestParseSpamAssassin_NoFlag(t *testing.T) {
	h := mail.Header{"X-Spam-Flag": []string{"NO"}}
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := gaugeValue(t, reg, "probe_spam_flag", "source", "spamassassin"); got != 0 {
		t.Fatalf("flag = %v, want 0", got)
	}
}

// TestBoolToFloat verifies the helper.
func TestBoolToFloat(t *testing.T) {
	if BoolToFloat(true) != 1 {
		t.Fatal("BoolToFloat(true) != 1")
	}
	if BoolToFloat(false) != 0 {
		t.Fatal("BoolToFloat(false) != 0")
	}
}

// TestFirstPublicSenderIP_EdgeCases covers nil/empty/private-only/malformed inputs.
func TestFirstPublicSenderIP_EdgeCases(t *testing.T) {
	cases := []struct {
		name     string
		received []string
		wantOK   bool
	}{
		{"nil slice", nil, false},
		{"empty slice", []string{}, false},
		{"no bracket IP", []string{"from mx.example.com (mx [no-ip]) by server; date"}, false},
		{"only private", []string{"from x ([192.168.1.1]) by server"}, false},
		{"only loopback", []string{"from x ([127.0.0.1]) by server"}, false},
		{"malformed bracket", []string{"from x ([not-an-ip]) by server"}, false},
		{"public IP", []string{"from x ([198.51.100.5]) by server"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, ok := FirstPublicSenderIP(tc.received)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v, want %v (ip=%v)", ok, tc.wantOK, ip)
			}
		})
	}
}

// TestParseZeroOne_NotOne verifies zero path.
func TestParseZeroOne_NotOne(t *testing.T) {
	if parseZeroOne("0") != 0 {
		t.Fatal("expected 0")
	}
	if parseZeroOne("garbage") != 0 {
		t.Fatal("expected 0 for garbage")
	}
}

// TestParseZeroOne_One verifies one path.
func TestParseZeroOne_One(t *testing.T) {
	if parseZeroOne("1") != 1 {
		t.Fatal("expected 1")
	}
}
