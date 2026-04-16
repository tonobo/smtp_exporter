// Package server exposes the exporter's HTTP surface.
package server

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	"gopkg.in/yaml.v3"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
	"github.com/tonobo/smtp_exporter/internal/prober"
)

// Handler wires HTTP routes to the prober and shared state.
type Handler struct {
	Config   *config.SafeConfig
	Resolver pdns.Resolver
	History  *History
	Reload   func() error

	unknownModule prometheus.Counter
	probeTotal    *prometheus.CounterVec
}

// NewHandler constructs a Handler and registers exporter-internal metrics.
func NewHandler(sc *config.SafeConfig, r pdns.Resolver, reload func() error, internalReg prometheus.Registerer) *Handler {
	h := &Handler{Config: sc, Resolver: r, Reload: reload, History: NewHistory(100)}
	h.unknownModule = prometheus.NewCounter(prometheus.CounterOpts{Name: "smtp_exporter_unknown_module_total", Help: "Count of probes requesting an unknown module."})
	h.probeTotal = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "smtp_exporter_probes_total", Help: "Count of probes by module and outcome."}, []string{"module", "outcome"})
	internalReg.MustRegister(h.unknownModule, h.probeTotal)
	return h
}

// Register mounts routes onto mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/probe", h.probe)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/config", h.config)
	mux.HandleFunc("/-/reload", h.reload)
	mux.HandleFunc("/-/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", h.index)
}

func (h *Handler) probe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("module")
	cfg := h.Config.Get()
	mod, ok := cfg.Modules[name]
	if !ok {
		h.unknownModule.Inc()
		http.Error(w, fmt.Sprintf("unknown module %q", name), http.StatusBadRequest)
		return
	}

	timeout := timeoutFromRequest(r, mod.Timeout)
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	reg := prometheus.NewRegistry()
	ok = prober.Run(ctx, mod, cfg.Global, h.Resolver, reg)

	outcome := "failure"
	if ok {
		outcome = "success"
	}
	h.probeTotal.WithLabelValues(name, outcome).Inc()

	debug := r.URL.Query().Get("debug") == "true"
	body := renderMetrics(reg)
	h.History.Add(name, mod.SMTP.MailTo, body, ok)

	if debug {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
		return
	}
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

func renderMetrics(reg *prometheus.Registry) string {
	mfs, _ := reg.Gather()
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		_ = enc.Encode(mf)
	}
	return buf.String()
}

func timeoutFromRequest(r *http.Request, module time.Duration) time.Duration {
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return time.Duration(f * float64(time.Second))
		}
	}
	return module
}

func (h *Handler) config(w http.ResponseWriter, _ *http.Request) {
	c := h.Config.Get()
	redacted := redactPasswords(c)
	out, err := yaml.Marshal(redacted)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(out)
}

func redactPasswords(c *config.Config) *config.Config {
	out := *c
	out.Modules = make(map[string]config.Module, len(c.Modules))
	for k, m := range c.Modules {
		if m.SMTP.Auth.Password != "" {
			m.SMTP.Auth.Password = "<redacted>"
		}
		if m.IMAP.Auth.Password != "" {
			m.IMAP.Auth.Password = "<redacted>"
		}
		out.Modules[k] = m
	}
	return &out
}

func (h *Handler) reload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html><head><title>smtp_exporter</title></head><body>`))
	_, _ = w.Write([]byte(`<h1>smtp_exporter</h1>`))
	_, _ = w.Write([]byte(`<ul><li><a href="/metrics">metrics</a></li><li><a href="/config">config</a></li></ul>`))
	_, _ = w.Write([]byte(`<h2>recent probes</h2><table border=1><tr><th>module</th><th>target</th><th>ok</th><th>at</th></tr>`))
	for _, e := range h.History.List() {
		_, _ = fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%v</td><td>%s</td></tr>",
			html.EscapeString(e.Module), html.EscapeString(e.Target), e.Success, e.Timestamp.UTC().Format(time.RFC3339))
	}
	_, _ = w.Write([]byte(`</table></body></html>`))
}
