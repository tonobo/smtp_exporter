package mail

import (
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// SpamMetrics is the Prometheus surface for spam-score parsing.
type SpamMetrics struct {
	Found *prometheus.GaugeVec
	Score *prometheus.GaugeVec
	Flag  *prometheus.GaugeVec
}

// NewSpamMetrics registers the metrics on reg.
func NewSpamMetrics(reg prometheus.Registerer) *SpamMetrics {
	m := &SpamMetrics{
		Found: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_spam_score_found",
			Help: "1 if a spam score from the given source was parsed.",
		}, []string{"source"}),
		Score: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_spam_score",
			Help: "Spam score reported by the given source.",
		}, []string{"source"}),
		Flag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_spam_flag",
			Help: "Boolean spam verdict from the given source.",
		}, []string{"source"}),
	}
	reg.MustRegister(m.Found, m.Score, m.Flag)
	return m
}

type spamParser func(h mail.Header, m *SpamMetrics) bool

var spamParsers = map[string]spamParser{
	"spamassassin": parseSpamAssassin,
	"rspamd":       parseRspamd,
	"gmail":        parseGmail,
	"microsoft":    parseMicrosoft,
	"barracuda":    parseBarracuda,
	"proofpoint":   parseProofpoint,
	"mimecast":     parseMimecast,
}

// ObserveSpam tries each parser; a parser is "hit" when it writes any metric.
func (m *SpamMetrics) ObserveSpam(h mail.Header) {
	for src, p := range spamParsers {
		if p(h, m) {
			m.Found.WithLabelValues(src).Set(1)
		}
	}
}

var (
	saStatusRE    = regexp.MustCompile(`(?i)score=([-+]?\d+(?:\.\d+)?)`)
	rspamdScoreRE = regexp.MustCompile(`([-+]?\d+(?:\.\d+)?)\s*/\s*[-+]?\d+`)
	barracudaRE   = regexp.MustCompile(`([-+]?\d+(?:\.\d+)?)`)
)

func parseSpamAssassin(h mail.Header, m *SpamMetrics) bool {
	hit := false
	if v := h.Get("X-Spam-Score"); v != "" {
		if s, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			m.Score.WithLabelValues("spamassassin").Set(s)
			hit = true
		}
	}
	if v := h.Get("X-Spam-Status"); v != "" {
		if !hit {
			if mt := saStatusRE.FindStringSubmatch(v); mt != nil {
				if s, err := strconv.ParseFloat(mt[1], 64); err == nil {
					m.Score.WithLabelValues("spamassassin").Set(s)
				}
			}
		}
		flag := strings.HasPrefix(strings.TrimSpace(v), "Yes")
		m.Flag.WithLabelValues("spamassassin").Set(boolToFloat(flag))
		hit = true
	}
	if v := h.Get("X-Spam-Flag"); v != "" {
		m.Flag.WithLabelValues("spamassassin").Set(boolToFloat(strings.EqualFold(strings.TrimSpace(v), "YES")))
		hit = true
	}
	return hit
}

func parseRspamd(h mail.Header, m *SpamMetrics) bool {
	for _, k := range []string{"X-Rspamd-Score", "X-Spamd-Result", "X-Rspamd-Result", "X-Spam-Result"} {
		v := h.Get(k)
		if v == "" {
			continue
		}
		if mt := rspamdScoreRE.FindStringSubmatch(v); mt != nil {
			if s, err := strconv.ParseFloat(mt[1], 64); err == nil {
				m.Score.WithLabelValues("rspamd").Set(s)
				return true
			}
		}
	}
	return false
}

func parseGmail(h mail.Header, m *SpamMetrics) bool {
	hit := false
	if v := h.Get("X-Gm-Spam"); v != "" {
		m.Flag.WithLabelValues("gmail").Set(parseZeroOne(v))
		hit = true
	}
	if v := h.Get("X-Gm-Phishy"); v != "" {
		m.Flag.WithLabelValues("gmail-phishy").Set(parseZeroOne(v))
		hit = true
	}
	return hit
}

func parseMicrosoft(h mail.Header, m *SpamMetrics) bool {
	if v := h.Get("X-MS-Exchange-Organization-SCL"); v != "" {
		if s, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			m.Score.WithLabelValues("microsoft").Set(s)
			return true
		}
	}
	return false
}

func parseBarracuda(h mail.Header, m *SpamMetrics) bool {
	if v := h.Get("X-Barracuda-Spam-Score"); v != "" {
		if mt := barracudaRE.FindStringSubmatch(v); mt != nil {
			if s, err := strconv.ParseFloat(mt[1], 64); err == nil {
				m.Score.WithLabelValues("barracuda").Set(s)
				return true
			}
		}
	}
	return false
}

func parseProofpoint(h mail.Header, m *SpamMetrics) bool {
	if h.Get("X-Proofpoint-Spam-Details") != "" {
		m.Flag.WithLabelValues("proofpoint").Set(1)
		return true
	}
	return false
}

func parseMimecast(h mail.Header, m *SpamMetrics) bool {
	if v := h.Get("X-Mimecast-Spam-Score"); v != "" {
		if s, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			m.Score.WithLabelValues("mimecast").Set(s)
			return true
		}
	}
	return false
}

func parseZeroOne(v string) float64 {
	if strings.TrimSpace(v) == "1" {
		return 1
	}
	return 0
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
