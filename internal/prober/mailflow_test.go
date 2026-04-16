package prober

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	sasl "github.com/emersion/go-sasl"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	esmtp "github.com/emersion/go-smtp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

// sizedReader is a minimal imap.LiteralReader implementation (matches imap_test.go pattern).
type sizedReader struct {
	*strings.Reader
	size int64
}

func (s *sizedReader) Size() int64 { return s.size }

// Fake SMTP backend that, on DATA, immediately copies the message into an
// in-memory IMAP mailbox so WaitForSubject can find it.
type e2eBackend struct {
	mu       sync.Mutex
	imapUser *imapmemserver.User
}

func (b *e2eBackend) NewSession(_ *esmtp.Conn) (esmtp.Session, error) {
	return &e2eSession{b: b}, nil
}

type e2eSession struct {
	b    *e2eBackend
	from string
	to   string
}

func (s *e2eSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *e2eSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		return nil
	}), nil
}
func (s *e2eSession) Mail(from string, _ *esmtp.MailOptions) error { s.from = from; return nil }
func (s *e2eSession) Rcpt(to string, _ *esmtp.RcptOptions) error   { s.to = to; return nil }
func (s *e2eSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	// Inject a synthetic Received: header with a public IP so DNSBL and
	// sender-ip extraction have something to work with.
	withReceived := fmt.Sprintf("Received: from probe.client (probe.client [198.51.100.7]) by test (smtp_exporter_test); %s\r\n%s",
		time.Now().Format(time.RFC1123Z), string(raw))
	// And an Authentication-Results header.
	withAuthRes := "Authentication-Results: test; spf=pass; dkim=pass; dmarc=pass\r\n" + withReceived

	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	return appendToMemUser(s.b.imapUser, "INBOX", []byte(withAuthRes))
}
func (*e2eSession) Reset()        {}
func (*e2eSession) Logout() error { return nil }

func TestMailflow_EndToEnd(t *testing.T) {
	// IMAP mem server
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
		}})
	il, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = imapSrv.Serve(il) }()
	defer func() { _ = imapSrv.Close(); il.Close() }()

	// SMTP fake server
	beh := &e2eBackend{imapUser: user}
	smtpSrv := esmtp.NewServer(beh)
	smtpSrv.Domain = "test"
	smtpSrv.AllowInsecureAuth = true
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = smtpSrv.Serve(sl) }()
	defer func() { _ = smtpSrv.Close(); sl.Close() }()

	// DNS fake: DNSBL zone "listed-test" lists 198.51.100.7; SPF TXT for example.org.
	r := pdns.NewFake()
	r.Host["7.100.51.198.listed-test"] = []string{"127.0.0.2"}
	r.TXT["example.org"] = []string{"v=spf1 ip4:198.51.100.0/24 -all"}

	mod := config.Module{
		Prober:  "mailflow",
		Timeout: 5 * time.Second,
		SMTP: config.SMTP{
			Server:   sl.Addr().String(),
			TLS:      "no",
			EHLO:     "test",
			MailFrom: "probe@example.org",
			MailTo:   "target@other",
			Auth:     config.Auth{Username: "u", Password: "p"},
		},
		IMAP: config.IMAP{
			Server:       il.Addr().String(),
			TLS:          "no",
			Mailbox:      "INBOX",
			PollInterval: 200 * time.Millisecond,
			Auth:         config.Auth{Username: "target@other", Password: "pass"},
		},
	}
	glb := config.Global{
		DNSBL:   config.DNSBL{Zones: []string{"listed-test"}},
		Cleanup: config.Cleanup{Enabled: true, MaxAge: time.Hour},
	}

	reg := prometheus.NewRegistry()
	ok := Run(context.Background(), mod, glb, r, reg)
	if !ok {
		dumpReg(t, reg)
		t.Fatal("probe failed")
	}

	assertGauge(t, reg, "probe_success", 1)
	assertGauge(t, reg, "probe_smtp_send_success", 1)
	assertGauge(t, reg, "probe_imap_message_received", 1)
	assertGaugeLabel(t, reg, "probe_dnsbl_listed", map[string]string{"zone": "listed-test", "ip": "198.51.100.7"}, 1)
	assertGaugeLabel(t, reg, "probe_spf_record_found", map[string]string{"domain": "example.org"}, 1)
	assertGaugeLabel(t, reg, "probe_auth_result_info", map[string]string{"check": "spf", "result": "pass"}, 1)
}

// appendToMemUser appends a raw message to the named mailbox of the given
// in-memory IMAP user using the sizedReader pattern from imap_test.go.
func appendToMemUser(user *imapmemserver.User, mailbox string, raw []byte) error {
	r := &sizedReader{strings.NewReader(string(raw)), int64(len(raw))}
	_, err := user.Append(mailbox, r, &imap.AppendOptions{Time: time.Now()})
	return err
}

func assertGauge(t *testing.T, reg *prometheus.Registry, name string, want float64) {
	t.Helper()
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, mt := range mf.GetMetric() {
			if got := mt.GetGauge().GetValue(); got == want {
				return
			}
		}
	}
	t.Fatalf("metric %s != %v", name, want)
}

func assertGaugeLabel(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string, want float64) {
	t.Helper()
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
			if mt.GetGauge().GetValue() == want {
				return
			}
		}
	}
	t.Fatalf("metric %s with %v != %v", name, labels, want)
}

func dumpReg(t *testing.T, reg *prometheus.Registry) {
	t.Helper()
	mfs, _ := reg.Gather()
	var b strings.Builder
	for _, mf := range mfs {
		fmt.Fprintf(&b, "%s:\n", mf.GetName())
		for _, mt := range mf.GetMetric() {
			fmt.Fprintf(&b, "  %v = %v\n", mt.GetLabel(), mt.GetGauge().GetValue())
		}
	}
	t.Logf("registry:\n%s", b.String())
}
