package authres

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestObserve_Gmail(t *testing.T) {
	raw, _ := os.ReadFile("../../testdata/auth_results/gmail.txt")
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	n := m.Observe(string(raw))
	if n != 3 {
		t.Fatalf("expected 3 checks observed, got %d", n)
	}

	want := `
# HELP probe_auth_result_found 1 if the given auth-results check was present.
# TYPE probe_auth_result_found gauge
probe_auth_result_found{check="dkim"} 1
probe_auth_result_found{check="dmarc"} 1
probe_auth_result_found{check="spf"} 1
`
	if err := testutil.GatherAndCompare(reg, stringReader(want), "probe_auth_result_found"); err != nil {
		t.Fatal(err)
	}
}

func TestObserve_Minimal_HasSPFOnly(t *testing.T) {
	raw, _ := os.ReadFile("../../testdata/auth_results/minimal.txt")
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	_ = m.Observe(string(raw))

	mfs, _ := reg.Gather()
	found := make(map[string]string)
	for _, mf := range mfs {
		if mf.GetName() != "probe_auth_result_info" {
			continue
		}
		for _, mt := range mf.GetMetric() {
			var check, result string
			for _, l := range mt.GetLabel() {
				if l.GetName() == "check" {
					check = l.GetValue()
				}
				if l.GetName() == "result" {
					result = l.GetValue()
				}
			}
			found[check] = result
		}
	}
	if found["spf"] != "softfail" || found["dkim"] != "none" || found["dmarc"] != "none" {
		t.Fatalf("got %#v", found)
	}
}

func stringReader(s string) io.Reader { return strings.NewReader(s) }
