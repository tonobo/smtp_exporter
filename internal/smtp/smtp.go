// Package smtp implements the "send" phase of a mailflow probe.
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	sasl "github.com/emersion/go-sasl"
	esmtp "github.com/emersion/go-smtp"
)

// Input fully describes one SMTP send attempt.
type Input struct {
	Server    string // host:port
	TLS       string // starttls|tls|no
	EHLO      string
	Username  string
	Password  string
	MailFrom  string
	MailTo    string
	Data      []byte
	TLSConfig *tls.Config
}

// Result captures everything we observed during the send.
type Result struct {
	Success            bool
	StatusCode         int
	EnhancedStatusCode int
	UsedTLS            bool
	TLSVersion         string
	TLSCertExpire      time.Time
	TLSFingerprint     string
	Message            string // server-side human-readable reply (from SMTPError.Message)
}

// Send connects, optionally negotiates TLS, authenticates if credentials are
// given, and delivers the message.
func Send(ctx context.Context, in Input) (Result, error) {
	res := Result{StatusCode: -1, EnhancedStatusCode: -1}

	c, err := dial(ctx, in)
	if err != nil {
		return res, err
	}
	defer func() { _ = c.Close() }()

	// For STARTTLS, initStartTLS already called hello() internally (with
	// "localhost"), then startTLS resets didHello — so we can call Hello()
	// again here with the configured EHLO name. For plain/tls, Hello() is
	// the first call, which triggers the greeting.
	if in.EHLO != "" {
		if err := c.Hello(in.EHLO); err != nil {
			return res, fmt.Errorf("ehlo: %w", err)
		}
	}

	if state, ok := c.TLSConnectionState(); ok {
		res.UsedTLS = true
		res.TLSVersion = tlsVersionName(state.Version)
		if len(state.PeerCertificates) > 0 {
			res.TLSCertExpire = state.PeerCertificates[0].NotAfter
			res.TLSFingerprint = fingerprintSHA256(state.PeerCertificates[0].Raw)
		}
	}

	if in.Username != "" {
		auth := sasl.NewPlainClient("", in.Username, in.Password)
		if err := c.Auth(auth); err != nil {
			recordSMTPErr(&res, err)
			return res, fmt.Errorf("auth: %w", err)
		}
	}

	if err := c.Mail(in.MailFrom, nil); err != nil {
		recordSMTPErr(&res, err)
		return res, fmt.Errorf("mail from: %w", err)
	}
	if err := c.Rcpt(in.MailTo, nil); err != nil {
		recordSMTPErr(&res, err)
		return res, fmt.Errorf("rcpt to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		recordSMTPErr(&res, err)
		return res, fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(in.Data); err != nil {
		return res, fmt.Errorf("write data: %w", err)
	}
	if err := w.Close(); err != nil {
		recordSMTPErr(&res, err)
		return res, fmt.Errorf("close data: %w", err)
	}
	_ = c.Quit()

	res.Success = true
	res.StatusCode = 250
	return res, nil
}

// dial creates an SMTP client connection according to the TLS mode.
// For "starttls", NewClientStartTLS handles the initial plaintext greeting and
// STARTTLS upgrade; after it returns, didHello is reset so Send can call
// Hello() with the configured EHLO name.
// For "tls", a direct TLS connection is made before handing off to NewClient.
// For "no", a plain TCP connection is used.
func dial(ctx context.Context, in Input) (*esmtp.Client, error) {
	d := &net.Dialer{}

	switch in.TLS {
	case "tls":
		cfg := in.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: hostOnly(in.Server), MinVersion: tls.VersionTLS12}
		}
		cfg = ensureTLSMin(cfg)
		td := &tls.Dialer{NetDialer: d, Config: cfg}
		conn, err := td.DialContext(ctx, "tcp", in.Server)
		if err != nil {
			return nil, err
		}
		return esmtp.NewClient(conn), nil

	case "starttls":
		cfg := in.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: hostOnly(in.Server), MinVersion: tls.VersionTLS12}
		}
		cfg = ensureTLSMin(cfg)
		conn, err := d.DialContext(ctx, "tcp", in.Server)
		if err != nil {
			return nil, err
		}
		// NewClientStartTLS: greets with "localhost", upgrades to TLS, then
		// resets didHello so the caller can issue Hello() with the real name.
		c, err := esmtp.NewClientStartTLS(conn, cfg)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
		return c, nil

	default: // "no"
		conn, err := d.DialContext(ctx, "tcp", in.Server)
		if err != nil {
			return nil, err
		}
		return esmtp.NewClient(conn), nil
	}
}

func recordSMTPErr(r *Result, err error) {
	var se *esmtp.SMTPError
	if errors.As(err, &se) {
		r.StatusCode = se.Code
		r.Message = se.Message
		if len(se.EnhancedCode) == 3 {
			r.EnhancedStatusCode = se.EnhancedCode[0]*100 + se.EnhancedCode[1]*10 + se.EnhancedCode[2]
		}
	}
}

func ensureTLSMin(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	if cfg.MinVersion == 0 {
		cfg = cfg.Clone()
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
