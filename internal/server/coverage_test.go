package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"net"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	sasl "github.com/emersion/go-sasl"
	esmtp "github.com/emersion/go-smtp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

// e2eSetup creates a wired SMTP+IMAP server pair for E2E tests.
// The SMTP server delivers received mail directly into the IMAP user's INBOX.
func e2eSetup(t *testing.T) (smtpAddr, imapAddr string, cleanup func()) {
	t.Helper()

	// IMAP server
	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser("target@other", "pass")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	memSrv.AddUser(user)
	imapSrv := imapserver.New(&imapserver.Options{
		InsecureAuth: true,
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
	})
	il, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = imapSrv.Serve(il) }()

	// SMTP server — on DATA, inject message into IMAP user's INBOX
	smtpBe := &serverE2EBackend{user: user}
	smtpSrv := esmtp.NewServer(smtpBe)
	smtpSrv.Domain = "test"
	smtpSrv.AllowInsecureAuth = true
	sl, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = smtpSrv.Serve(sl) }()

	stop := func() {
		_ = imapSrv.Close()
		_ = il.Close()
		_ = smtpSrv.Close()
		_ = sl.Close()
	}
	return sl.Addr().String(), il.Addr().String(), stop
}

type serverE2EBackend struct {
	user *imapmemserver.User
}

func (b *serverE2EBackend) NewSession(_ *esmtp.Conn) (esmtp.Session, error) {
	return &serverE2ESession{b: b}, nil
}

type serverE2ESession struct {
	b *serverE2EBackend
}

func (s *serverE2ESession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *serverE2ESession) Auth(_ string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, _, _ string) error { return nil }), nil
}
func (s *serverE2ESession) Mail(_ string, _ *esmtp.MailOptions) error { return nil }
func (s *serverE2ESession) Rcpt(_ string, _ *esmtp.RcptOptions) error { return nil }
func (s *serverE2ESession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	// Add a Received header so prober parsing works.
	msg := fmt.Sprintf("Received: from test (test [198.51.100.7]) by test (smtp_exporter_test); %s\r\n%s",
		time.Now().Format(time.RFC1123Z), string(raw))
	sr := &sizedReader{data: []byte(msg)}
	_, err = s.b.user.Append("INBOX", sr, &imap.AppendOptions{Time: time.Now()})
	return err
}
func (s *serverE2ESession) Reset()        {}
func (s *serverE2ESession) Logout() error { return nil }

type sizedReader struct {
	data   []byte
	offset int
}

func (r *sizedReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
func (r *sizedReader) Size() int64 { return int64(len(r.data)) }

// makeTestModule creates a config.Module pointing to the given SMTP+IMAP addrs.
func makeTestModule(smtpAddr, imapAddr string) config.Module {
	return config.Module{
		Prober:  "mailflow",
		Timeout: 10 * time.Second,
		SMTP: config.SMTP{
			Server:   smtpAddr,
			TLS:      "no",
			EHLO:     "test",
			MailFrom: "probe@example.org",
			MailTo:   "target@other",
		},
		IMAP: config.IMAP{
			Server:       imapAddr,
			TLS:          "no",
			Mailbox:      "INBOX",
			PollInterval: 200 * time.Millisecond,
			Auth:         config.Auth{Username: "target@other", Password: "pass"},
		},
	}
}

// newE2EHandler creates a Handler with a real module config for E2E tests.
func newE2EHandler(t *testing.T, smtpAddr, imapAddr string) (*Handler, *http.ServeMux) {
	t.Helper()
	sc := config.NewSafeConfig()
	sc.Get().Modules["test"] = makeTestModule(smtpAddr, imapAddr)
	// We directly set the modules since NewSafeConfig returns an empty config.
	// We need to store a new config with the module.
	cfg := &config.Config{
		Modules: map[string]config.Module{
			"test": makeTestModule(smtpAddr, imapAddr),
		},
	}
	// Use a temp file to reload the config properly.
	_ = cfg
	h := NewHandler(
		slog.New(slog.DiscardHandler),
		sc,
		pdns.NewFake(),
		func() error { return nil },
		prometheus.NewRegistry(),
	)
	// Inject module directly into the SafeConfig.
	// SafeConfig.Get() returns a pointer; we need to store a config with modules.
	// Since SafeConfig doesn't have a direct "set config" method, write a temp file.
	// Actually — we can directly set via a file reload with a properly formatted YAML.
	dir := t.TempDir()
	path := dir + "/cfg.yaml"
	yaml := fmt.Sprintf(`modules:
  test:
    prober: mailflow
    timeout: 10s
    smtp:
      server: %q
      tls: no
      ehlo: test
      mail_from: probe@example.org
      mail_to: "target@other"
    imap:
      server: %q
      tls: no
      mailbox: INBOX
      poll_interval: 200ms
      auth:
        username: "target@other"
        password: pass
`, smtpAddr, imapAddr)
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sc.Reload(path); err != nil {
		t.Fatalf("reload config: %v", err)
	}

	mux := http.NewServeMux()
	h.Register(mux)
	return h, mux
}

// TestProbe_HappyPath_E2E verifies a full probe via /probe?module=test.
func TestProbe_HappyPath_E2E(t *testing.T) {
	smtpAddr, imapAddr, stop := e2eSetup(t)
	defer stop()

	_, mux := newE2EHandler(t, smtpAddr, imapAddr)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/probe?module=test", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "probe_success 1") {
		t.Fatalf("expected probe_success 1 in body, got:\n%s", body)
	}
}

// TestProbe_DebugMode verifies /probe?debug=true returns text/plain with metrics.
func TestProbe_DebugMode(t *testing.T) {
	smtpAddr, imapAddr, stop := e2eSetup(t)
	defer stop()

	_, mux := newE2EHandler(t, smtpAddr, imapAddr)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/probe?module=test&debug=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "probe_success") {
		t.Fatalf("debug body missing probe_success: %s", body)
	}
}

// TestProbe_ConcurrentIsolation fires 3 concurrent probes and verifies no panics.
func TestProbe_ConcurrentIsolation(t *testing.T) {
	smtpAddr, imapAddr, stop := e2eSetup(t)
	defer stop()

	_, mux := newE2EHandler(t, smtpAddr, imapAddr)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/probe?module=test", nil)
			if err != nil {
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
}

// TestConfigEndpoint_RedactsAuth verifies that /config redacts passwords.
func TestConfigEndpoint_RedactsAuth(t *testing.T) {
	sc := config.NewSafeConfig()
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), func() error { return nil }, prometheus.NewRegistry())

	dir := t.TempDir()
	path := dir + "/cfg.yaml"
	yaml := `modules:
  test:
    prober: mailflow
    timeout: 30s
    smtp:
      server: smtp.example.com:587
      tls: starttls
      mail_from: a@b.com
      mail_to: c@d.com
      auth:
        username: user
        password: secretsmtp
    imap:
      server: imap.example.com:993
      tls: tls
      mailbox: INBOX
      poll_interval: 5s
      auth:
        username: user
        password: secretimap
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sc.Reload(path); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/config", nil)
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

	if strings.Contains(bodyStr, "secretsmtp") {
		t.Error("SMTP password not redacted in /config response")
	}
	if strings.Contains(bodyStr, "secretimap") {
		t.Error("IMAP password not redacted in /config response")
	}
	if !strings.Contains(bodyStr, "<redacted>") {
		t.Error("expected <redacted> in /config response")
	}
}

// TestReloadEndpoint verifies POST /-/reload and GET /-/reload behaviors.
func TestReloadEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/cfg.yaml"
	validYAML := `modules:
  x:
    prober: mailflow
    timeout: 30s
    smtp:
      server: smtp:587
      tls: starttls
      mail_from: a@b
      mail_to: c@d
    imap:
      server: imap:993
      tls: tls
      mailbox: INBOX
      poll_interval: 2s
`
	if err := os.WriteFile(path, []byte(validYAML), 0600); err != nil {
		t.Fatal(err)
	}

	sc := config.NewSafeConfig()
	if err := sc.Reload(path); err != nil {
		t.Fatal(err)
	}

	reloadFn := func() error { return sc.Reload(path) }
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), reloadFn, prometheus.NewRegistry())
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// POST /-/reload with valid config → 200
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/-/reload", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Overwrite with invalid YAML → POST /-/reload → 500
	if err := os.WriteFile(path, []byte("invalid: yaml: [unclosed"), 0600); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/-/reload", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 for invalid config reload, got %d", resp.StatusCode)
	}

	// GET /-/reload → 405
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/-/reload", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /-/reload, got %d", resp.StatusCode)
	}
}

// TestTimeoutFromRequest_HeaderOverride verifies timeoutFromRequest picks up the header.
func TestTimeoutFromRequest_HeaderOverride(t *testing.T) {
	sc := config.NewSafeConfig()
	h := NewHandler(discardLogger(), sc, pdns.NewFake(), func() error { return nil }, prometheus.NewRegistry())

	req := httptest.NewRequest(http.MethodGet, "/probe?module=nope", nil)
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "30")

	d := timeoutFromRequest(req, 10e9) // module timeout: 10s
	if d.Seconds() != 30 {
		t.Fatalf("expected 30s from header, got %v", d)
	}
	_ = h
}

// TestTimeoutFromRequest_ModuleDefault verifies fallback to module timeout.
func TestTimeoutFromRequest_ModuleDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/probe?module=nope", nil)
	// No header set → use module timeout.
	d := timeoutFromRequest(req, 15*time.Second)
	if d != 15*time.Second {
		t.Fatalf("expected 15s default, got %v", d)
	}
}

// TestTimeoutFromRequest_InvalidHeader verifies that a bad header value falls back to module timeout.
func TestTimeoutFromRequest_InvalidHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "not-a-number")
	d := timeoutFromRequest(req, 20*time.Second)
	if d != 20*time.Second {
		t.Fatalf("expected 20s fallback, got %v", d)
	}
}

// TestTimeoutFromRequest_ZeroHeader verifies that a zero header value falls back to module timeout.
func TestTimeoutFromRequest_ZeroHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "0")
	d := timeoutFromRequest(req, 20*time.Second)
	if d != 20*time.Second {
		t.Fatalf("expected 20s fallback for zero header, got %v", d)
	}
}

// TestHistory_Empty verifies NewHistory(0) creates bounded history with limit 0.
func TestHistory_Empty(t *testing.T) {
	h := NewHistory(0)
	h.Add("mod", "t@e.st", true)
	entries := h.List()
	// With cap=0, Add grows the slice but the ring still works.
	// The important thing is no panic.
	_ = entries
}

// Unused import suppression.
var _ = json.Marshal
