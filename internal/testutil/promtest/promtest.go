// Package promtest provides assertion helpers for prometheus.Registry contents.
//
// This package is internal test infrastructure. Its API is unstable
// and not covered by the project's semver promises — it may change
// or be removed at any time without notice.
package promtest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// GaugeVal returns the value of a gauge with the given labels, failing the
// test if not found.
func GaugeVal(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	v, ok := find(reg, name, labels)
	if !ok {
		Dump(t, reg)
		t.Fatalf("metric %s%s not found", name, labelStr(labels))
	}
	return v
}

// CounterVal is GaugeVal for counter-typed metrics.
func CounterVal(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	return GaugeVal(t, reg, name, labels)
}

// AssertGauge asserts that a gauge has a specific value.
func AssertGauge(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string, want float64) {
	t.Helper()
	got, ok := find(reg, name, labels)
	if !ok {
		seen := allValues(reg, name)
		t.Fatalf("metric %s%s not found; values seen for %s: %v", name, labelStr(labels), name, seen)
	}
	if got != want {
		t.Fatalf("metric %s%s: got %v, want %v", name, labelStr(labels), got, want)
	}
}

// Dump prints all metrics in the registry — useful when an assertion fails.
func Dump(t *testing.T, reg *prometheus.Registry) {
	t.Helper()
	dump(t, reg)
}

func find(reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	next:
		for _, mt := range mf.GetMetric() {
			for k, v := range labels {
				found := false
				for _, lp := range mt.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == v {
						found = true
						break
					}
				}
				if !found {
					continue next
				}
			}
			if g := mt.GetGauge(); g != nil {
				return g.GetValue(), true
			}
			if c := mt.GetCounter(); c != nil {
				return c.GetValue(), true
			}
		}
	}
	return 0, false
}

func allValues(reg *prometheus.Registry, name string) []float64 {
	mfs, _ := reg.Gather()
	var out []float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, mt := range mf.GetMetric() {
			if g := mt.GetGauge(); g != nil {
				out = append(out, g.GetValue())
			}
			if c := mt.GetCounter(); c != nil {
				out = append(out, c.GetValue())
			}
		}
	}
	return out
}

func labelStr(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func dump(t *testing.T, reg *prometheus.Registry) {
	t.Helper()
	mfs, _ := reg.Gather()
	var b strings.Builder
	for _, mf := range mfs {
		fmt.Fprintf(&b, "%s:\n", mf.GetName())
		for _, mt := range mf.GetMetric() {
			v := 0.0
			if g := mt.GetGauge(); g != nil {
				v = g.GetValue()
			}
			if c := mt.GetCounter(); c != nil {
				v = c.GetValue()
			}
			fmt.Fprintf(&b, "  %v = %v\n", mt.GetLabel(), v)
		}
	}
	t.Logf("registry:\n%s", b.String())
}
