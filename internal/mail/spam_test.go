package mail

import (
	"bytes"
	"net/mail"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/testutil/promtest"
)

func FuzzSpamObserve(f *testing.F) {
	// Real-world examples from fixtures.
	f.Add("Yes, score=7.2 required=5.0 tests=BAYES_99")
	f.Add("3.5 / 15.0")
	f.Add("default: false [3.50 / 15.00]")
	f.Add("0")
	f.Add("")

	headerNames := []string{
		"X-Spam-Status", "X-Spam-Score", "X-Spam-Flag", "X-Spam-Level",
		"X-Rspamd-Score", "X-Rspamd-Result", "X-Spamd-Result",
		"X-Gm-Spam", "X-Gm-Phishy",
		"X-MS-Exchange-Organization-SCL",
		"X-Barracuda-Spam-Score", "X-Barracuda-Spam-Status",
		"X-Proofpoint-Spam-Details",
		"X-Mimecast-Spam-Score",
	}

	f.Fuzz(func(t *testing.T, val string) {
		// Try the fuzzed value against every known spam header name.
		// Property: no parser panics, no matter how garbage the value.
		for _, name := range headerNames {
			h := mail.Header{name: []string{val}}
			reg := prometheus.NewRegistry()
			m := NewSpamMetrics(reg)
			m.ObserveSpam(h) // must not panic
		}
	})
}

func loadSpamHeader(t *testing.T, path string) mail.Header {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m.Header
}

func TestSpamAssassin(t *testing.T) {
	h := loadSpamHeader(t, "../../testdata/spam_headers/spamassassin.eml")
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := promtest.GaugeVal(t, reg, "probe_spam_score", map[string]string{"source": "spamassassin"}); got != 7.2 {
		t.Fatalf("score=%v", got)
	}
	if got := promtest.GaugeVal(t, reg, "probe_spam_flag", map[string]string{"source": "spamassassin"}); got != 1 {
		t.Fatalf("flag=%v", got)
	}
}

func TestRspamd(t *testing.T) {
	h := loadSpamHeader(t, "../../testdata/spam_headers/rspamd.eml")
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := promtest.GaugeVal(t, reg, "probe_spam_score", map[string]string{"source": "rspamd"}); got != 3.5 {
		t.Fatalf("score=%v", got)
	}
}

func TestGmail(t *testing.T) {
	h := loadSpamHeader(t, "../../testdata/spam_headers/gmail.eml")
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := promtest.GaugeVal(t, reg, "probe_spam_flag", map[string]string{"source": "gmail"}); got != 0 {
		t.Fatalf("gm-spam=%v", got)
	}
}

func TestMicrosoft(t *testing.T) {
	h := loadSpamHeader(t, "../../testdata/spam_headers/microsoft.eml")
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := promtest.GaugeVal(t, reg, "probe_spam_score", map[string]string{"source": "microsoft"}); got != 1 {
		t.Fatalf("SCL=%v", got)
	}
}

func TestBarracuda(t *testing.T) {
	h := loadSpamHeader(t, "../../testdata/spam_headers/barracuda.eml")
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := promtest.GaugeVal(t, reg, "probe_spam_score", map[string]string{"source": "barracuda"}); got != 2.30 {
		t.Fatalf("score=%v", got)
	}
}

// TestStalwart verifies that Stalwart's X-Spam-Result header (rspamd format)
// is parsed by the rspamd parser.
func TestStalwart(t *testing.T) {
	h := loadSpamHeader(t, "../../testdata/spam_headers/stalwart.eml")
	reg := prometheus.NewRegistry()
	m := NewSpamMetrics(reg)
	m.ObserveSpam(h)
	if got := promtest.GaugeVal(t, reg, "probe_spam_score", map[string]string{"source": "rspamd"}); got != 3.5 {
		t.Fatalf("score=%v, want 3.5", got)
	}
}
