# smtp_exporter

Blackbox-style Prometheus exporter for end-to-end mail-flow monitoring. One HTTP probe executes the full flow (SMTP send → IMAP receive) and emits metrics for TLS properties, SPF records, DNSBL listings of the sender IP, Authentication-Results (SPF/DKIM/DMARC), and spam-scanner verdicts from common providers.

## ⚠️ Vibecoded

This project is a from-scratch rewrite produced via AI-assisted coding (Claude). Review carefully before production deployment. Not upstream-compatible with `kmille/smtp_exporter`.

## How it works

On each scrape of `/probe?module=<name>`, the exporter:

1. Builds a probe mail with a UUID in `Subject`, `Message-ID`, and `X-Probe-ID`.
2. Looks up the SPF record of the sender domain (concurrent with step 3).
3. Sends the mail via SMTP to the configured MAIL FROM / RCPT TO. Records TLS version, cert expiry, fingerprint, status codes.
4. Polls the configured IMAP mailbox every `poll_interval` for a message with the exact Subject. Records delivery time.
5. Fetches the received mail and:
   - Extracts the first public IP from the `Received:` header chain.
   - For each DNSBL zone in the global config, queries `<reversed-ip>.<zone>`.
   - Parses `Authentication-Results` for spf/dkim/dmarc.
   - Parses spam-scanner headers (SpamAssassin, rspamd, Gmail, Microsoft, Barracuda, Proofpoint, Mimecast).
6. Deletes the probe mail + sweeps any `X-Probe-ID` mail older than `global.cleanup.max_age`.

The scrape returns the metric set produced during the probe.

## Install

```bash
go install github.com/tonobo/smtp_exporter/cmd/smtp_exporter@latest
```

Or via container:

```bash
docker run --rm -p 9125:9125 -v $PWD/smtp_exporter.yml:/etc/smtp_exporter.yml \
  ghcr.io/tonobo/smtp_exporter:main \
  --config.file=/etc/smtp_exporter.yml
```

## Configuration

```yaml
global:
  dnsbl:
    zones:
      - zen.spamhaus.org
      - bl.spamcop.net
      - b.barracudacentral.org
  cleanup:
    enabled: true
    max_age: 24h

modules:
  example:
    prober: mailflow
    timeout: 180s
    smtp:
      server: mail.example.org:587
      tls: starttls         # starttls | tls | no
      ehlo: mail.example.org
      auth:
        username: probe@example.org
        password: secret
      mail_from: probe@example.org
      mail_to: target@example.com
    imap:
      server: imap.example.com:993
      tls: tls
      auth:
        username: target@example.com
        password: secret
      mailbox: INBOX
      poll_interval: 2s
```

Reload with `SIGHUP` or `POST /-/reload`.

### Environment variable expansion

`${VAR}` and `$VAR` placeholders in the config file are expanded at load time
via `os.ExpandEnv`. Useful for keeping secrets out of the YAML:

```yaml
modules:
  example:
    smtp:
      auth:
        password: ${SMTP_PASSWORD}
```

Unset variables expand to empty strings — verify env vars are populated to
avoid silent auth failures.

### Gmail setup

Gmail free accounts work, but only with an **App Password**, not the regular account password:

1. Enable 2-Step Verification on the Google account.
2. Visit <https://myaccount.google.com/apppasswords> and create a 16-character App Password.
3. Use it as `auth.password` for both SMTP and IMAP.
4. SMTP: `smtp.gmail.com:587` with `tls: starttls`.
5. IMAP: `imap.gmail.com:993` with `tls: tls`.

Google disabled "Less secure apps" in 2022; regular-password authentication does not work. OAuth2 / XOAUTH2 is not supported yet.

## Metrics

All probe-specific metrics are prefixed `probe_`. `*_found` gauges are `0|1` so alerting can use `== 0` without `absent()`. `*_info` gauges carry labels with identifiers; the value is always `1` when set.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `probe_success` | gauge | — | 1 iff SMTP send and IMAP receive both succeeded. |
| `probe_duration_seconds` | gauge | — | Total probe wall-clock. |
| `probe_phase_duration_seconds` | gauge | `phase` | Duration per phase (`smtp`, `imap`, `spf`, `dnsbl`, `parse`). |
| `probe_smtp_send_success` | gauge | — | 1 if SMTP send succeeded. |
| `probe_smtp_status_code` | gauge | — | SMTP reply code; -1 on pre-reply failure. |
| `probe_smtp_enhanced_status_code` | gauge | — | Enhanced status as flat int; -1 if absent. |
| `probe_smtp_tls` | gauge | — | 1 if the connection used TLS. |
| `probe_smtp_tls_version_info` | gauge | `version` | 1 for the observed TLS version. |
| `probe_smtp_tls_cert_expire_seconds` | gauge | — | Peer cert NotAfter as unix seconds. |
| `probe_smtp_tls_cert_fingerprint_info` | gauge | `fingerprint_sha256` | 1 for the peer cert fingerprint. |
| `probe_imap_login_success` | gauge | — | 1 if IMAP LOGIN succeeded. |
| `probe_imap_message_received` | gauge | — | 1 if the probe mail was found. |
| `probe_imap_delivery_seconds` | gauge | — | Seconds from SMTP done to IMAP detected. |
| `probe_imap_cleanup_deleted_count` | gauge | — | Number of mails deleted in cleanup. |
| `probe_imap_folder_info` | gauge | `folder` | 1 for the folder where probe mail was detected. Values: `inbox`, `spam`, `junk`, `other`. |
| `probe_imap_spam_detected` | gauge | — | 1 if probe was delivered to a spam/junk folder. Useful as alert signal. |
| `probe_imap_spam_trained_total` | counter | — | 1 if a spam-to-inbox MOVE was issued for this probe (move_from_spam). Resets per scrape. |
| `probe_imap_spam_train_failed_total` | counter | — | 1 if the spam-to-inbox MOVE failed for this probe. |
| `probe_sender_ip_found` | gauge | — | 1 if a public sender IP was extracted. |
| `probe_sender_ip_info` | gauge | `ip` | 1 for the extracted sender IP. |
| `probe_dnsbl_checked` | gauge | `zone` | 1 if the zone was queried. |
| `probe_dnsbl_listed` | gauge | `zone`, `ip` | 1 if listed in the zone. |
| `probe_dnsbl_lookup_duration_seconds` | gauge | `zone` | Per-zone lookup duration. |
| `probe_spf_record_found` | gauge | `domain` | 1 if an SPF TXT record was found. |
| `probe_spf_record_info` | gauge | `domain`, `record` | 1 per observed record text. |
| `probe_auth_result_found` | gauge | `check` | 1 if the check was present (`spf`, `dkim`, `dmarc`). |
| `probe_auth_result_info` | gauge | `check`, `result` | 1 per observed (check,result) pair. |
| `probe_spam_score_found` | gauge | `source` | 1 if the source reported a score. |
| `probe_spam_score` | gauge | `source` | Spam score. |
| `probe_spam_flag` | gauge | `source` | Boolean verdict where available. |

### Example Prometheus scrape config

```yaml
scrape_configs:
  - job_name: smtp_exporter
    metrics_path: /probe
    scrape_interval: 5m
    scrape_timeout: 3m
    params:
      module: [example]
    static_configs:
      - targets: [example]
    relabel_configs:
      - source_labels: [__address__]
        target_label: module
      - target_label: __address__
        replacement: smtp_exporter.monitoring.svc.cluster.local:9125
```

`scrape_timeout` must exceed module `timeout`.

## Multi-folder detection

The probe searches INBOX first, then any folder marked `\Junk` via IMAP
SPECIAL-USE (RFC 6154), then well-known names (`Spam`, `Junk`, `[Gmail]/Spam`,
`Junk Mail`, `Junk E-mail`). The first match wins. `probe_imap_folder_info{folder="spam"} 1`
is the signal that authentication passed but the recipient's filter quarantined
the mail.

### Spam-training mode

Set `global.cleanup.move_from_spam: true` to auto-move probe mail from
a spam/junk folder back to INBOX after detection. For Gmail this acts
as a "Not spam" training signal (weaker than clicking the web UI
button, but measurable over time). Opt-in; default off.

When enabled, the per-probe mark-deleted+expunge cleanup is skipped for
spam→inbox moves; the age-based sweep (max_age) handles eventual
cleanup so moved mail stays in the inbox long enough to count as
positive engagement.

## Probe mail headers

Every probe carries these identification and priority headers so receivers
can handle it appropriately:

- `Auto-Submitted: auto-generated` (RFC 3834) — machine-generated
- `X-Auto-Response-Suppress: All` — suppress OOF/read/delivery receipts on
  Exchange/Outlook to prevent mail loops
- `User-Agent: smtp_exporter/<version> (+repo URL)` — honest software ID
- `Feedback-ID: probe:<sender-domain>:<module>:smtp_exporter` — Gmail
  Postmaster Tools bucket, isolates probe traffic from your main reputation
- `MT-Priority: -4 (NON-URGENT)` (RFC 6758) — low priority hint for MTAs
- `Importance: Low` / `X-Priority: 5` — low priority hints for mail clients

Message-ID is generated with the sender's From-domain (not the pod hostname)
so the domain aligns with the SPF/DKIM identities and doesn't trigger
MSGID_FROM_MTA_HEADER-style anti-spam rules.

## Development

```bash
make build
make test
make test-cover   # writes coverage.html
```

No live-server tests are run in CI; unit tests use in-process emersion SMTP/IMAP servers and a fake DNS resolver.

## License

Apache-2.0.
