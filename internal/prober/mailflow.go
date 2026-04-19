// Package prober orchestrates a single mailflow probe.
package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
	"github.com/tonobo/smtp_exporter/internal/imap"
	pmail "github.com/tonobo/smtp_exporter/internal/mail"
	psmtp "github.com/tonobo/smtp_exporter/internal/smtp"
)

// Run executes the mailflow probe for the given module and records all
// observations on reg. Returns whether the probe succeeded overall.
func Run(
	ctx context.Context, logger *slog.Logger, m config.Module, moduleName string, g config.Global, r pdns.Resolver, reg *prometheus.Registry,
) bool {
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
	built := pmail.Build(pmail.Input{
		ProbeID: probeID, From: m.SMTP.MailFrom, To: m.SMTP.MailTo, Hostname: hostname, ModuleName: moduleName,
	})

	// SPF lookup runs concurrently with SMTP send.
	spfCtx, cancelSPF := context.WithCancel(ctx)
	defer cancelSPF()
	spfDone := make(chan pdns.SPFResult, 1)
	go func() {
		t0 := time.Now()
		res := pdns.LookupSPF(spfCtx, r, pmail.DomainOf(m.SMTP.MailFrom))
		fm.phaseDuration.WithLabelValues("spf").Set(time.Since(t0).Seconds())
		select {
		case spfDone <- res:
		case <-spfCtx.Done():
		}
	}()

	// Build TLS configs — a misconfigured ca_file aborts the probe rather than
	// silently falling back to the system pool.
	smtpTLS, err := config.BuildTLSConfig(m.SMTP.TLSConfig, hostOnly(m.SMTP.Server))
	if err != nil {
		logger.Warn("smtp tls_config invalid", "module", moduleName, "error", err.Error())
		return false
	}
	imapTLS, err := config.BuildTLSConfig(m.IMAP.TLSConfig, hostOnly(m.IMAP.Server))
	if err != nil {
		logger.Warn("imap tls_config invalid", "module", moduleName, "error", err.Error())
		return false
	}

	// SMTP send
	smtpStart := time.Now()
	sendRes, sendErr := psmtp.Send(ctx, psmtp.Input{
		Server: m.SMTP.Server, TLS: m.SMTP.TLS, EHLO: m.SMTP.EHLO,
		Username: m.SMTP.Auth.Username, Password: m.SMTP.Auth.Password,
		MailFrom: m.SMTP.MailFrom, MailTo: m.SMTP.MailTo,
		Data:      []byte(built.RFC5322),
		TLSConfig: smtpTLS,
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
		msg := sendRes.Message
		if msg == "" && sendErr != nil {
			msg = sendErr.Error()
		}
		logger.Warn("smtp send failed",
			"module", moduleName,
			"status_code", sendRes.StatusCode,
			"enhanced_status_code", sendRes.EnhancedStatusCode,
			"server_message", msg,
		)
		return false
	}
	sendDone := time.Now()

	// Discover IMAP folder layout (INBOX + spam/junk folder if present).
	imapIn := imap.Input{
		Server: m.IMAP.Server, TLS: m.IMAP.TLS,
		Username: m.IMAP.Auth.Username, Password: m.IMAP.Auth.Password,
		Mailbox: m.IMAP.Mailbox, PollInterval: m.IMAP.PollInterval,
		TLSConfig: imapTLS,
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
	// Search by the FIRST hex chunk of the ProbeID (8 chars), not the full
	// dash-separated UUID. Reason: Stalwart's IMAP SEARCH SUBJECT goes
	// through Postgres FTS, which (a) splits UUIDs on dashes into 5 separate
	// tokens, and (b) takes 3+ minutes to index newly-arrived mail. Until
	// FTS indexes, only single-token substring matches work — a search for
	// the full "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" returns 0 hits while
	// "xxxxxxxx" returns the message instantly. The 8-char hex chunk has
	// 32-bit uniqueness, more than enough for our probe rate (collisions
	// effectively impossible at <200 mails/day with immediate cleanup).
	imapStart := time.Now()
	needle := built.ProbeID
	if dash := strings.IndexByte(needle, '-'); dash > 0 {
		needle = needle[:dash]
	}
	raw, folderFound, foundUID, err := imap.WaitForSubject(ctx, imapIn, needle, pollFolders)
	fm.phaseDuration.WithLabelValues("imap").Set(time.Since(imapStart).Seconds())
	if err != nil {
		logger.Warn("imap wait failed", "module", moduleName, "error", err.Error())
		fm.imapLoginSuccess.Set(boolToFloat(!strings.Contains(err.Error(), "login")))
		fm.imapMessageReceived.Set(0)
		runCleanup(ctx, logger, moduleName, m, g, fm, m.IMAP.Mailbox, imapTLS)
		return false
	}
	fm.imapLoginSuccess.Set(1)
	fm.imapMessageReceived.Set(1)
	fm.imapDelivery.Set(time.Since(sendDone).Seconds())

	// Emit folder placement metrics.
	spamMoved := false
	if folderFound != "" {
		category := classifyFolder(folderFound)
		fm.imapFolderInfo.WithLabelValues(category).Set(1)
		if category == "spam" || category == "junk" {
			fm.imapSpamDetected.Set(1)
			logger.Info("probe mail landed in spam/junk folder", "module", moduleName, "folder", folderFound)

			// Spam-training: move probe mail back to INBOX to signal "not spam".
			if g.Cleanup.MoveFromSpam {
				moved, err := imap.MoveToInbox(ctx, imapIn, folderFound, foundUID)
				if err != nil {
					logger.Warn("spam-to-inbox move failed",
						"module", moduleName,
						"folder", folderFound,
						"error", err.Error())
					fm.imapSpamTrainFailed.Inc()
				} else if moved {
					logger.Info("moved probe from spam to inbox",
						"module", moduleName,
						"folder", folderFound,
						"uid", fmt.Sprint(foundUID))
					fm.imapSpamTrained.Inc()
					spamMoved = true
				}
			}
		}
	}

	// Parse received mail
	parseStart := time.Now()
	parseReceivedMail(ctx, fm, raw, r, g)
	fm.phaseDuration.WithLabelValues("parse").Set(time.Since(parseStart).Seconds())

	// Cleanup — target the folder where the message was found.
	// When move_from_spam triggered a successful MOVE, the message is now in
	// INBOX and the source spam folder is already empty. Skip the per-probe
	// mark-deleted+expunge so the mail stays in INBOX long enough for the
	// age-based sweep (max_age) to act as a positive engagement signal.
	// The sweep will eventually remove it from INBOX.
	if !spamMoved {
		cleanupMailbox := m.IMAP.Mailbox
		if folderFound != "" {
			cleanupMailbox = folderFound
		}
		runCleanup(ctx, logger, moduleName, m, g, fm, cleanupMailbox, imapTLS)
	} else {
		// Still run the age-based sweep on INBOX to clean up old probes.
		runCleanup(ctx, logger, moduleName, m, g, fm, m.IMAP.Mailbox, imapTLS)
	}

	fm.success.Set(1)
	success = true
	return true
}

func parseReceivedMail(ctx context.Context, fm *flowMetrics, raw []byte, r pdns.Resolver, g config.Global) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return
	}

	// Parse Received headers once; share with all consumers.
	received := pmail.ParseReceivedHeaders(raw)

	// Sender IP from Received chain
	ip, ok := pmail.FirstPublicSenderIP(received)
	if ok {
		fm.senderIPFound.Set(1)
		fm.senderIPInfo.WithLabelValues(ip.String()).Set(1)

		// DNSBL
		dnsblStart := time.Now()
		results := pdns.QueryBlacklist(ctx, r, ip, g.DNSBL.Zones)
		fm.phaseDuration.WithLabelValues("dnsbl").Set(time.Since(dnsblStart).Seconds())
		for _, res := range results {
			fm.dnsblChecked.WithLabelValues(res.Zone).Set(1)
			fm.dnsblDuration.WithLabelValues(res.Zone).Set(res.Duration.Seconds())
			fm.dnsblListed.WithLabelValues(res.Zone, ip.String()).Set(boolToFloat(res.Listed))
			if res.ResponseCode != "" {
				fm.dnsblResultCode.WithLabelValues(res.Zone, ip.String(), res.ResponseCode).Set(1)
			}
		}
	} else {
		fm.senderIPFound.Set(0)
	}

	// Authentication-Results
	fm.authres.Observe(msg.Header.Get("Authentication-Results"))

	// Spam
	fm.spam.ObserveSpam(msg.Header)
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

func runCleanup(
	ctx context.Context, logger *slog.Logger, moduleName string, m config.Module, g config.Global, fm *flowMetrics, mailbox string,
	imapTLS *tls.Config,
) {
	if !g.Cleanup.Enabled {
		return
	}
	n, err := imap.Sweep(ctx, imap.Input{
		Server: m.IMAP.Server, TLS: m.IMAP.TLS,
		Username: m.IMAP.Auth.Username, Password: m.IMAP.Auth.Password,
		Mailbox: mailbox, PollInterval: m.IMAP.PollInterval,
		TLSConfig: imapTLS,
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

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
