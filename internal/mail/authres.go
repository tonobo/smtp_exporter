package mail

import (
	"github.com/emersion/go-msgauth/authres"
	"github.com/prometheus/client_golang/prometheus"
)

// AuthResMetrics holds the gauge vectors produced by auth-result parsing.
type AuthResMetrics struct {
	Found *prometheus.GaugeVec
	Info  *prometheus.GaugeVec
}

// NewAuthResMetrics registers the metrics on reg.
func NewAuthResMetrics(reg prometheus.Registerer) *AuthResMetrics {
	m := &AuthResMetrics{
		Found: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_auth_result_found",
			Help: "1 if the given auth-results check was present.",
		}, []string{"check"}),
		Info: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_auth_result_info",
			Help: "1 per observed (check,result) pair from Authentication-Results.",
		}, []string{"check", "result"}),
	}
	reg.MustRegister(m.Found, m.Info)
	return m
}

// Observe parses a single Authentication-Results header value and emits
// metrics for each of spf / dkim / dmarc present in it. Returns the number
// of checks observed.
func (m *AuthResMetrics) Observe(headerValue string) int {
	if headerValue == "" {
		return 0
	}
	_, results, err := authres.Parse(headerValue)
	if err != nil {
		return 0
	}
	seen := map[string]struct{}{}
	count := 0
	for _, r := range results {
		var check, result string
		switch v := r.(type) {
		case *authres.SPFResult:
			check, result = "spf", string(v.Value)
		case *authres.DKIMResult:
			check, result = "dkim", string(v.Value)
		case *authres.DMARCResult:
			check, result = "dmarc", string(v.Value)
		default:
			continue
		}
		if _, ok := seen[check]; ok {
			continue
		}
		seen[check] = struct{}{}
		m.Found.WithLabelValues(check).Set(1)
		m.Info.WithLabelValues(check, result).Set(1)
		count++
	}
	return count
}
