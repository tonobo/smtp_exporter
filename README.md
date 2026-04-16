# smtp_exporter

Blackbox-style Prometheus exporter for end-to-end mail-flow monitoring: sends a probe email via SMTP, waits for it on IMAP, and emits metrics covering TLS, DNSBL, SPF, Authentication-Results (SPF/DKIM/DMARC), and spam-scanner verdicts.

## ⚠️ Vibecoded

This project is a from-scratch rewrite produced via AI-assisted coding (Claude). Review carefully before production deployment. Not upstream-compatible with `kmille/smtp_exporter`.

## Status

Work in progress. See `docs/superpowers/specs/2026-04-16-smtp-exporter-rewrite-design.md` in the pinfra repo for the design.
