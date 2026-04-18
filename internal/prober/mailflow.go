// Package prober orchestrates a single mailflow probe.
package prober

import (
	"context"
	"log/slog"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
	"github.com/tonobo/smtp_exporter/internal/dnsbl"
	"github.com/tonobo/smtp_exporter/internal/imap"
	"github.com/tonobo/smtp_exporter/internal/message"
	psmtp "github.com/tonobo/smtp_exporter/internal/smtp"
	"github.com/tonobo/smtp_exporter/internal/spf"
)

// Run executes the mailflow probe for the given module and records all
// observations on reg. Returns whether the probe succeeded overall.
func Run(ctx context.Context, logger *slog.Logger, m config.Module, moduleName string, g config.Global, r pdns.Resolver, reg *prometheus.Registry) bool {
	fm := newFlowMetrics(reg)
	start := time.Now()
	success := false
	logger.Info("probe start", "module", moduleName)
	defer func() {
		fm.duration.Set(time.Since(start).Seconds())
		logger.Info("probe complete", "module", moduleName, "success", success, "duration_seconds", time.Since(start).Seconds())
	}()

	hostname, _ := os.Hostname()
	probeID := uuid.New().String()
	built := message.Build(message.Input{
		ProbeID: probeID, From: m.SMTP.MailFrom, To: m.SMTP.MailTo, Hostname: hostname,
	})

	// SPF lookup runs concurrently with SMTP send.
	spfDone := make(chan spf.Result, 1)
	go func() {
		t0 := time.Now()
		res := spf.Lookup(ctx, r, domainOf(m.SMTP.MailFrom))
		fm.phaseDuration.WithLabelValues("spf").Set(time.Since(t0).Seconds())
		spfDone <- res
	}()

	// SMTP send
	smtpStart := time.Now()
	sendRes, _ := psmtp.Send(ctx, psmtp.Input{
		Server: m.SMTP.Server, TLS: m.SMTP.TLS, EHLO: m.SMTP.EHLO,
		Username: m.SMTP.Auth.Username, Password: m.SMTP.Auth.Password,
		MailFrom: m.SMTP.MailFrom, MailTo: m.SMTP.MailTo,
		Data: []byte(built.RFC5322),
	})
	fm.phaseDuration.WithLabelValues("smtp").Set(time.Since(smtpStart).Seconds())
	writeSMTPMetrics(fm, sendRes)

	// Wait for SPF, emit metrics.
	if res := <-spfDone; res.Found {
		fm.spfRecordFound.WithLabelValues(res.Domain).Set(1)
		fm.spfRecordInfo.WithLabelValues(res.Domain, res.Record).Set(1)
	} else if res.Err == nil {
		fm.spfRecordFound.WithLabelValues(res.Domain).Set(0)
	}

	if !sendRes.Success {
		logger.Warn("smtp send failed",
			"module", moduleName,
			"status_code", sendRes.StatusCode,
			"enhanced_status_code", sendRes.EnhancedStatusCode,
			"server_message", sendRes.Message,
		)
		return false
	}
	sendDone := time.Now()

	// Discover IMAP folder layout (INBOX + spam/junk folder if present).
	imapIn := imap.ClientInput{
		Server: m.IMAP.Server, TLS: m.IMAP.TLS,
		Username: m.IMAP.Auth.Username, Password: m.IMAP.Auth.Password,
		Mailbox: m.IMAP.Mailbox, PollInterval: m.IMAP.PollInterval,
	}
	folders, err := imap.DiscoverFolders(ctx, imapIn)
	if err != nil {
		logger.Warn("imap folder discovery failed", "module", moduleName, "error", err.Error())
		// Non-fatal: fall back to INBOX-only polling.
		folders = imap.Folders{Inbox: m.IMAP.Mailbox}
	}
	pollFolders := []string{folders.Inbox}
	if folders.Spam != "" && folders.Spam != folders.Inbox {
		pollFolders = append(pollFolders, folders.Spam)
	}

	// IMAP receive — poll INBOX first, then spam folder if discovered.
	imapStart := time.Now()
	raw, folderFound, err := imap.WaitForSubject(ctx, imapIn, built.Subject, pollFolders)
	fm.phaseDuration.WithLabelValues("imap").Set(time.Since(imapStart).Seconds())
	if err != nil {
		logger.Warn("imap wait failed", "module", moduleName, "error", err.Error())
		fm.imapLoginSuccess.Set(boolToFloat(!strings.Contains(err.Error(), "login")))
		fm.imapMessageReceived.Set(0)
		runCleanup(ctx, logger, moduleName, m, g, fm, m.IMAP.Mailbox)
		return false
	}
	fm.imapLoginSuccess.Set(1)
	fm.imapMessageReceived.Set(1)
	fm.imapDelivery.Set(time.Since(sendDone).Seconds())

	// Emit folder placement metrics.
	if folderFound != "" {
		category := classifyFolder(folderFound)
		fm.imapFolderInfo.WithLabelValues(category).Set(1)
		if category == "spam" || category == "junk" {
			fm.imapSpamDetected.Set(1)
			logger.Info("probe mail landed in spam/junk folder", "module", moduleName, "folder", folderFound)
		}
	}

	// Parse received mail
	parseStart := time.Now()
	parseReceivedMail(fm, raw, r, g)
	fm.phaseDuration.WithLabelValues("parse").Set(time.Since(parseStart).Seconds())

	// Cleanup — target the folder where the message was found.
	cleanupMailbox := m.IMAP.Mailbox
	if folderFound != "" {
		cleanupMailbox = folderFound
	}
	runCleanup(ctx, logger, moduleName, m, g, fm, cleanupMailbox)

	fm.success.Set(1)
	success = true
	return true
}

func parseReceivedMail(fm *flowMetrics, raw []byte, r pdns.Resolver, g config.Global) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return
	}

	// Sender IP from Received chain
	ip, ok := message.FirstPublicSenderIP(raw)
	if ok {
		fm.senderIPFound.Set(1)
		fm.senderIPInfo.WithLabelValues(ip.String()).Set(1)

		// DNSBL
		dnsblStart := time.Now()
		results := dnsbl.Query(context.Background(), r, ip, g.DNSBL.Zones)
		fm.phaseDuration.WithLabelValues("dnsbl").Set(time.Since(dnsblStart).Seconds())
		for _, res := range results {
			fm.dnsblChecked.WithLabelValues(res.Zone).Set(1)
			fm.dnsblDuration.WithLabelValues(res.Zone).Set(res.Duration.Seconds())
			fm.dnsblListed.WithLabelValues(res.Zone, ip.String()).Set(boolToFloat(res.Listed))
		}
	} else {
		fm.senderIPFound.Set(0)
	}

	// Authentication-Results
	fm.authres.Observe(msg.Header.Get("Authentication-Results"))

	// Spam
	fm.spam.Observe(msg.Header)
}

// classifyFolder maps a raw IMAP folder name to one of the canonical
// category strings: "inbox", "spam", "junk", or "other".
func classifyFolder(name string) string {
	lower := strings.ToLower(name)
	switch {
	case name == "INBOX":
		return "inbox"
	case strings.Contains(lower, "spam"):
		return "spam"
	case strings.Contains(lower, "junk"):
		return "junk"
	default:
		return "other"
	}
}

func runCleanup(ctx context.Context, logger *slog.Logger, moduleName string, m config.Module, g config.Global, fm *flowMetrics, mailbox string) {
	if !g.Cleanup.Enabled {
		return
	}
	n, err := imap.Sweep(ctx, imap.ClientInput{
		Server: m.IMAP.Server, TLS: m.IMAP.TLS,
		Username: m.IMAP.Auth.Username, Password: m.IMAP.Auth.Password,
		Mailbox: mailbox, PollInterval: m.IMAP.PollInterval,
	}, g.Cleanup.MaxAge)
	if err != nil {
		logger.Warn("imap cleanup failed", "module", moduleName, "error", err.Error())
		return
	}
	fm.imapCleanupDeleted.Set(float64(n))
}

func writeSMTPMetrics(fm *flowMetrics, r psmtp.Result) {
	fm.smtpSendSuccess.Set(boolToFloat(r.Success))
	fm.smtpStatus.Set(float64(r.StatusCode))
	fm.smtpEnhancedStatus.Set(float64(r.EnhancedStatusCode))
	fm.smtpTLS.Set(boolToFloat(r.UsedTLS))
	if r.UsedTLS {
		fm.smtpTLSVersion.WithLabelValues(r.TLSVersion).Set(1)
	}
	if !r.TLSCertExpire.IsZero() {
		fm.smtpTLSCertExpire.Set(float64(r.TLSCertExpire.Unix()))
	}
	if r.TLSFingerprint != "" {
		fm.smtpTLSFingerprint.WithLabelValues(r.TLSFingerprint).Set(1)
	}
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return addr
	}
	return addr[at+1:]
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
