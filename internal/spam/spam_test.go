package spam

import (
	"net/mail"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func loadHeader(t *testing.T, path string) mail.Header {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m.Header
}

func TestSpamAssassin(t *testing.T) {
	h := loadHeader(t, "../../testdata/spam_headers/spamassassin.eml")
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.Observe(h)
	if got := gaugeValue(t, reg, "probe_spam_score", "source", "spamassassin"); got != 7.2 {
		t.Fatalf("score=%v", got)
	}
	if got := gaugeValue(t, reg, "probe_spam_flag", "source", "spamassassin"); got != 1 {
		t.Fatalf("flag=%v", got)
	}
}

func TestRspamd(t *testing.T) {
	h := loadHeader(t, "../../testdata/spam_headers/rspamd.eml")
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.Observe(h)
	if got := gaugeValue(t, reg, "probe_spam_score", "source", "rspamd"); got != 3.5 {
		t.Fatalf("score=%v", got)
	}
}

func TestGmail(t *testing.T) {
	h := loadHeader(t, "../../testdata/spam_headers/gmail.eml")
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.Observe(h)
	if got := gaugeValue(t, reg, "probe_spam_flag", "source", "gmail"); got != 0 {
		t.Fatalf("gm-spam=%v", got)
	}
}

func TestMicrosoft(t *testing.T) {
	h := loadHeader(t, "../../testdata/spam_headers/microsoft.eml")
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.Observe(h)
	if got := gaugeValue(t, reg, "probe_spam_score", "source", "microsoft"); got != 1 {
		t.Fatalf("SCL=%v", got)
	}
}

func TestBarracuda(t *testing.T) {
	h := loadHeader(t, "../../testdata/spam_headers/barracuda.eml")
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.Observe(h)
	if got := gaugeValue(t, reg, "probe_spam_score", "source", "barracuda"); got != 2.30 {
		t.Fatalf("score=%v", got)
	}
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name, labelKey, labelVal string) float64 {
	t.Helper()
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, mt := range mf.GetMetric() {
			for _, l := range mt.GetLabel() {
				if l.GetName() == labelKey && l.GetValue() == labelVal {
					return mt.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("metric %s{%s=%s} not found", name, labelKey, labelVal)
	return 0
}
