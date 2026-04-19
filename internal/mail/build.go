// Package mail builds and parses probe mails and extracts mail-content metrics.
package mail

import (
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/common/version"
)

// Input describes a single probe mail.
type Input struct {
	ProbeID    string
	From       string
	To         string
	Hostname   string
	ModuleName string    // used for Feedback-ID header
	Now        time.Time // optional; defaults to time.Now()
}

// Built is the concrete message ready to hand to an SMTP DATA command.
type Built struct {
	ProbeID string
	Subject string
	RFC5322 string // full headers + body, CRLF line endings
}

// DomainOf returns the domain part of an email address, or the full string if
// no '@' is present.
func DomainOf(addr string) string {
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		return addr[at+1:]
	}
	return addr
}

// versionString returns the build-injected version, falling back to "dev"
// when building outside the release pipeline.
func versionString() string {
	if v := version.Version; v != "" {
		return v
	}
	return "dev"
}

// feedbackID formats a Gmail Postmaster Tools Feedback-ID per the Google
// specification: "a:b:c:SenderId" where SenderId is the mandatory tail
// (5–15 chars) used as the aggregation bucket. We use "smtp_exporter" as
// the SenderId (13 chars, constant across all probes) so Google can isolate
// probe traffic from the sender domain's main reputation stream. The first
// three fields embed the per-probe context: campaign="probe",
// customer=<sender-domain>, other=<module-name>.
func feedbackID(moduleName, from string) string {
	domain := DomainOf(from)
	if domain == "" {
		domain = "unknown"
	}
	if moduleName == "" {
		moduleName = "unknown"
	}
	return fmt.Sprintf("probe:%s:%s:smtp_exporter", domain, moduleName)
}

// Build produces a probe-mail with all required identification headers.
func Build(in Input) Built {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	subj := fmt.Sprintf("[smtp_exporter] %s", in.ProbeID)
	fromDomain := DomainOf(in.From)
	msgID := fmt.Sprintf("<%s@%s>", in.ProbeID, fromDomain)

	var b strings.Builder
	w := func(k, v string) { b.WriteString(k); b.WriteString(": "); b.WriteString(v); b.WriteString("\r\n") }
	w("From", in.From)
	w("To", in.To)
	w("Subject", subj)
	w("Date", now.UTC().Format(time.RFC1123Z))
	w("Message-ID", msgID)
	w("X-Probe-ID", in.ProbeID)

	// Identification headers — tell receivers this is machine-generated
	// monitoring traffic, not user-to-user correspondence.

	// RFC 3834 — machine-generated monitoring mail. Receivers (especially
	// Gmail) use this to exclude the message from engagement-based
	// reputation calculations while still honouring auth (SPF/DKIM/DMARC).
	w("Auto-Submitted", "auto-generated")
	// MS Exchange/Outlook convention: suppress OOO replies, read receipts,
	// and delivery receipts to prevent mail loops and noise.
	w("X-Auto-Response-Suppress", "All")
	// RFC 2076 informational header: honest software identification.
	w("User-Agent", fmt.Sprintf("smtp_exporter/%s (+https://github.com/tonobo/smtp_exporter)", versionString()))
	// Gmail Postmaster Tools: bucket probe traffic separately from
	// user-to-user mail to protect the sender domain's reputation.
	w("Feedback-ID", feedbackID(in.ModuleName, in.From))

	// Priority headers — yield to user mail in MTA queues and clients.
	w("MT-Priority", "-4 (NON-URGENT)") // RFC 6758 low-priority MTA hint
	w("Importance", "Low")              // RFC 2156 client hint
	w("X-Priority", "5")                // de-facto client priority (1=high, 5=low)

	w("MIME-Version", "1.0")
	w("Content-Type", "text/plain; charset=utf-8")
	b.WriteString("\r\n")
	b.WriteString("This is an automated probe message from smtp_exporter.\r\n")

	return Built{ProbeID: in.ProbeID, Subject: subj, RFC5322: b.String()}
}
