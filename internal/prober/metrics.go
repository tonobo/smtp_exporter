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

	// sender ip
	senderIPFound prometheus.Gauge
	senderIPInfo  *prometheus.GaugeVec

	// dnsbl
	dnsblChecked  *prometheus.GaugeVec
	dnsblListed   *prometheus.GaugeVec
	dnsblDuration *prometheus.GaugeVec

	// spf record
	spfRecordFound *prometheus.GaugeVec
	spfRecordInfo  *prometheus.GaugeVec

	// sub-metrics
	authres *authres.Metrics
	spam    *spam.Metrics
}

func newFlowMetrics(reg prometheus.Registerer) *flowMetrics {
	m := &flowMetrics{
		success:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_success", Help: "1 if SMTP send and IMAP receive both succeeded."}),
		duration:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_duration_seconds", Help: "Total probe duration."}),
		phaseDuration: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_phase_duration_seconds", Help: "Time spent in each phase."}, []string{"phase"}),

		smtpSendSuccess:    prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_smtp_send_success", Help: "1 if the SMTP send succeeded."}),
		smtpStatus:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_smtp_status_code", Help: "SMTP reply code; -1 on pre-reply failure."}),
		smtpEnhancedStatus: prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_smtp_enhanced_status_code", Help: "Enhanced SMTP status code flattened to int; -1 if absent."}),
		smtpTLS:            prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_smtp_tls", Help: "1 if the SMTP connection used TLS."}),
		smtpTLSVersion:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_smtp_tls_version_info", Help: "1 for the observed TLS version."}, []string{"version"}),
		smtpTLSCertExpire:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_smtp_tls_cert_expire_seconds", Help: "Peer cert NotAfter as unix seconds."}),
		smtpTLSFingerprint: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_smtp_tls_cert_fingerprint_info", Help: "1 for the peer cert SHA-256 fingerprint."}, []string{"fingerprint_sha256"}),

		imapLoginSuccess:    prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_imap_login_success", Help: "1 if IMAP LOGIN succeeded."}),
		imapMessageReceived: prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_imap_message_received", Help: "1 if the probe mail was found on IMAP."}),
		imapDelivery:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_imap_delivery_seconds", Help: "Seconds from SMTP send-done to IMAP detection."}),
		imapCleanupDeleted:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_imap_cleanup_deleted_count", Help: "Number of mails deleted in cleanup (target + sweep)."}),
		imapFolderInfo:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_imap_folder_info", Help: "1 for the folder where the probe message was detected (inbox, spam, junk, other)."}, []string{"folder"}),
		imapSpamDetected:    prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_imap_spam_detected", Help: "1 if the probe message was delivered but landed in a spam/junk folder."}),

		senderIPFound: prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_sender_ip_found", Help: "1 if a public sender IP was extracted from the Received chain."}),
		senderIPInfo:  prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_sender_ip_info", Help: "1 for the extracted sender IP."}, []string{"ip"}),

		dnsblChecked:  prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_dnsbl_checked", Help: "1 if the zone was queried."}, []string{"zone"}),
		dnsblListed:   prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_dnsbl_listed", Help: "1 if the IP is listed in the zone."}, []string{"zone", "ip"}),
		dnsblDuration: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_dnsbl_lookup_duration_seconds", Help: "DNSBL lookup duration per zone."}, []string{"zone"}),

		spfRecordFound: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_spf_record_found", Help: "1 if an SPF TXT record was found."}, []string{"domain"}),
		spfRecordInfo:  prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "probe_spf_record_info", Help: "1 per observed (domain,record) pair."}, []string{"domain", "record"}),
	}
	reg.MustRegister(
		m.success, m.duration, m.phaseDuration,
		m.smtpSendSuccess, m.smtpStatus, m.smtpEnhancedStatus,
		m.smtpTLS, m.smtpTLSVersion, m.smtpTLSCertExpire, m.smtpTLSFingerprint,
		m.imapLoginSuccess, m.imapMessageReceived, m.imapDelivery, m.imapCleanupDeleted,
		m.imapFolderInfo, m.imapSpamDetected,
		m.senderIPFound, m.senderIPInfo,
		m.dnsblChecked, m.dnsblListed, m.dnsblDuration,
		m.spfRecordFound, m.spfRecordInfo,
	)
	m.authres = authres.NewMetrics(reg)
	m.spam = spam.NewMetrics(reg)
	return m
}
