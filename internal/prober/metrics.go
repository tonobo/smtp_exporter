package prober

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonobo/smtp_exporter/internal/authres"
	"github.com/tonobo/smtp_exporter/internal/spam"
)

type flowMetrics struct {
	// overall
	success       prometheus.Gauge
	duration      prometheus.Gauge
	phaseDuration *prometheus.GaugeVec

	// smtp
	smtpSendSuccess    prometheus.Gauge
	smtpStatus         prometheus.Gauge
	smtpEnhancedStatus prometheus.Gauge
	smtpTLS            prometheus.Gauge
	smtpTLSVersion     *prometheus.GaugeVec
	smtpTLSCertExpire  prometheus.Gauge
	smtpTLSFingerprint *prometheus.GaugeVec

	// imap
	imapLoginSuccess    prometheus.Gauge
	imapMessageReceived prometheus.Gauge
	imapDelivery        prometheus.Gauge
	imapCleanupDeleted  prometheus.Gauge
	imapFolderInfo      *prometheus.GaugeVec
	imapSpamDetected    prometheus.Gauge
	// imapSpamTrained and imapSpamTrainFailed are counters. Because the
	// Prometheus registry is created fresh per probe scrape (stateless), these
	// counters reset on every probe invocation — they signal whether *this*
	// probe attempt triggered a spam-to-inbox move, not a cumulative total.
	imapSpamTrained     prometheus.Counter
	imapSpamTrainFailed prometheus.Counter

	// sender ip
	senderIPFound prometheus.Gauge
	senderIPInfo  *prometheus.GaugeVec

	// dnsbl
	dnsblChecked    *prometheus.GaugeVec
	dnsblListed     *prometheus.GaugeVec
	dnsblDuration   *prometheus.GaugeVec
	dnsblResultCode *prometheus.GaugeVec

	// spf record
	spfRecordFound *prometheus.GaugeVec
	spfRecordInfo  *prometheus.GaugeVec

	// sub-metrics
	authres *authres.Metrics
	spam    *spam.Metrics
}

func g(name, help string) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
}

func gv(name, help string, labels []string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

func ct(name, help string) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
}

func newFlowMetrics(reg prometheus.Registerer) *flowMetrics {
	m := &flowMetrics{
		success:       g("probe_success", "1 if SMTP send and IMAP receive both succeeded."),
		duration:      g("probe_duration_seconds", "Total probe duration."),
		phaseDuration: gv("probe_phase_duration_seconds", "Time spent in each phase.", []string{"phase"}),

		smtpSendSuccess:    g("probe_smtp_send_success", "1 if the SMTP send succeeded."),
		smtpStatus:         g("probe_smtp_status_code", "SMTP reply code; -1 on pre-reply failure."),
		smtpEnhancedStatus: g("probe_smtp_enhanced_status_code", "Enhanced SMTP status code flattened to int; -1 if absent."),
		smtpTLS:            g("probe_smtp_tls", "1 if the SMTP connection used TLS."),
		smtpTLSVersion:     gv("probe_smtp_tls_version_info", "1 for the observed TLS version.", []string{"version"}),
		smtpTLSCertExpire:  g("probe_smtp_tls_cert_expire_seconds", "Peer cert NotAfter as unix seconds."),
		smtpTLSFingerprint: gv(
			"probe_smtp_tls_cert_fingerprint_info", "1 for the peer cert SHA-256 fingerprint.", []string{"fingerprint_sha256"},
		),

		imapLoginSuccess:    g("probe_imap_login_success", "1 if IMAP LOGIN succeeded."),
		imapMessageReceived: g("probe_imap_message_received", "1 if the probe mail was found on IMAP."),
		imapDelivery:        g("probe_imap_delivery_seconds", "Seconds from SMTP send-done to IMAP detection."),
		imapCleanupDeleted:  g("probe_imap_cleanup_deleted_count", "Number of mails deleted in cleanup (target + sweep)."),
		imapFolderInfo: gv(
			"probe_imap_folder_info",
			"1 for the folder where the probe message was detected (inbox, spam, junk, other).",
			[]string{"folder"},
		),
		imapSpamDetected:    g("probe_imap_spam_detected", "1 if the probe message was delivered but landed in a spam/junk folder."),
		imapSpamTrained:     ct("probe_imap_spam_trained_total", "1 if a spam-to-inbox MOVE was issued for this probe (move_from_spam)."),
		imapSpamTrainFailed: ct("probe_imap_spam_train_failed_total", "1 if the spam-to-inbox MOVE failed for this probe."),

		senderIPFound: g("probe_sender_ip_found", "1 if a public sender IP was extracted from the Received chain."),
		senderIPInfo:  gv("probe_sender_ip_info", "1 for the extracted sender IP.", []string{"ip"}),

		dnsblChecked:  gv("probe_dnsbl_checked", "1 if the zone was queried.", []string{"zone"}),
		dnsblListed:   gv("probe_dnsbl_listed", "1 if the IP is listed in the zone.", []string{"zone", "ip"}),
		dnsblDuration: gv("probe_dnsbl_lookup_duration_seconds", "DNSBL lookup duration per zone.", []string{"zone"}),
		dnsblResultCode: gv(
			"probe_dnsbl_result_code",
			// Rate-limit codes like 127.255.255.254 are not listings; this label lets you distinguish them.
			"1 for the raw A-record response code returned by a DNSBL zone.",
			[]string{"zone", "ip", "code"},
		),

		spfRecordFound: gv("probe_spf_record_found", "1 if an SPF TXT record was found.", []string{"domain"}),
		spfRecordInfo:  gv("probe_spf_record_info", "1 per observed (domain,record) pair.", []string{"domain", "record"}),
	}
	reg.MustRegister(
		m.success, m.duration, m.phaseDuration,
		m.smtpSendSuccess, m.smtpStatus, m.smtpEnhancedStatus,
		m.smtpTLS, m.smtpTLSVersion, m.smtpTLSCertExpire, m.smtpTLSFingerprint,
		m.imapLoginSuccess, m.imapMessageReceived, m.imapDelivery, m.imapCleanupDeleted,
		m.imapFolderInfo, m.imapSpamDetected,
		m.imapSpamTrained, m.imapSpamTrainFailed,
		m.senderIPFound, m.senderIPInfo,
		m.dnsblChecked, m.dnsblListed, m.dnsblDuration, m.dnsblResultCode,
		m.spfRecordFound, m.spfRecordInfo,
	)
	m.authres = authres.NewMetrics(reg)
	m.spam = spam.NewMetrics(reg)
	return m
}
