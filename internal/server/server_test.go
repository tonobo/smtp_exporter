package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestProbe_UnknownModule(t *testing.T) {
	sc := config.NewSafeConfig()
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), func() error { return nil }, prometheus.NewRegistry())
	mux := http.NewServeMux()
	h.Register(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/probe?module=nope", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestHealth(t *testing.T) {
	sc := config.NewSafeConfig()
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), func() error { return nil }, prometheus.NewRegistry())
	mux := http.NewServeMux()
	h.Register(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/-/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("body: %q", body)
	}
}

func TestRedactPasswords(t *testing.T) {
	c := &config.Config{
		Modules: map[string]config.Module{
			"test": {
				Prober:  "mailflow",
				Timeout: 30e9, // 30s
				SMTP: config.SMTP{
					Server:   "smtp.example.com:587",
					TLS:      "starttls",
					MailFrom: "a@b.com",
					MailTo:   "c@d.com",
					Auth:     config.Auth{Username: "user", Password: "secretsmtp"},
				},
				IMAP: config.IMAP{
					Server:       "imap.example.com:993",
					TLS:          "tls",
					Mailbox:      "INBOX",
					Auth:         config.Auth{Username: "user", Password: "secretimap"},
					PollInterval: 5e9,
				},
			},
		},
	}

	out := redactPasswords(c)
	m := out.Modules["test"]
	if m.SMTP.Auth.Password != "<redacted>" {
		t.Errorf("SMTP password not redacted: %q", m.SMTP.Auth.Password)
	}
	if m.IMAP.Auth.Password != "<redacted>" {
		t.Errorf("IMAP password not redacted: %q", m.IMAP.Auth.Password)
	}
	// Username should be preserved.
	if m.SMTP.Auth.Username != "user" {
		t.Errorf("SMTP username was changed: %q", m.SMTP.Auth.Username)
	}
}

func TestHistory_Bounded(t *testing.T) {
	h := NewHistory(100)
	for i := 0; i < 150; i++ {
		h.Add(fmt.Sprintf("mod%d", i), "target@example.com", i%2 == 0)
	}
	entries := h.List()
	if len(entries) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(entries))
	}
	// The oldest 50 (mod0..mod49) should be gone; mod50 should be the first.
	if entries[0].Module != "mod50" {
		t.Errorf("first entry module = %q, want mod50", entries[0].Module)
	}
	if entries[99].Module != "mod149" {
		t.Errorf("last entry module = %q, want mod149", entries[99].Module)
	}
}

func TestProbe_MethodNotAllowed(t *testing.T) {
	sc := config.NewSafeConfig()
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), func() error { return nil }, prometheus.NewRegistry())
	mux := http.NewServeMux()
	h.Register(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/probe?module=x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestProbe_TimeoutHeader(t *testing.T) {
	sc := config.NewSafeConfig()
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), func() error { return nil }, prometheus.NewRegistry())

	req := httptest.NewRequest(http.MethodGet, "/probe?module=nope", nil)
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "30")

	// timeoutFromRequest is an internal helper; call it directly to verify.
	d := timeoutFromRequest(req, 10e9) // module timeout: 10s
	if d.Seconds() != 30 {
		t.Fatalf("expected 30s from header, got %v", d)
	}
	_ = h // suppress unused warning
}

func TestIndexPage_EscapesHTML(t *testing.T) {
	sc := config.NewSafeConfig()
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), func() error { return nil }, prometheus.NewRegistry())
	// Add a history entry with an HTML-injection module name.
	h.History.Add("<script>alert(1)</script>", "target@example.com", false)

	mux := http.NewServeMux()
	h.Register(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "<script>") {
		t.Error("raw <script> tag found in index page — HTML not escaped")
	}
	if !strings.Contains(bodyStr, "&lt;script&gt;") {
		t.Error("escaped &lt;script&gt; not found in index page")
	}
}
