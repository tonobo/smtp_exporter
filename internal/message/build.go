// Package message builds and parses probe mails.
package message

import (
	"fmt"
	"strings"
	"time"
)

// Input describes a single probe mail.
type Input struct {
	ProbeID  string
	From     string
	To       string
	Hostname string
	Now      time.Time // optional; defaults to time.Now()
}

// Built is the concrete message ready to hand to an SMTP DATA command.
type Built struct {
	ProbeID string
	Subject string
	RFC5322 string // full headers + body, CRLF line endings
}

// Build produces a probe-mail with all required identification headers.
func Build(in Input) Built {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	subj := fmt.Sprintf("[smtp_exporter] %s", in.ProbeID)
	msgID := fmt.Sprintf("<%s@%s>", in.ProbeID, in.Hostname)

	var b strings.Builder
	w := func(k, v string) { b.WriteString(k); b.WriteString(": "); b.WriteString(v); b.WriteString("\r\n") }
	w("From", in.From)
	w("To", in.To)
	w("Subject", subj)
	w("Date", now.UTC().Format(time.RFC1123Z))
	w("Message-ID", msgID)
	w("X-Probe-ID", in.ProbeID)
	w("MIME-Version", "1.0")
	w("Content-Type", "text/plain; charset=utf-8")
	b.WriteString("\r\n")
	b.WriteString("This is an automated probe message from smtp_exporter.\r\n")

	return Built{ProbeID: in.ProbeID, Subject: subj, RFC5322: b.String()}
}
