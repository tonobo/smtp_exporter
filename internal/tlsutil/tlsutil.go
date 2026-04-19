// Package tlsutil bridges the on-disk TLS config schema into a *tls.Config.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/tonobo/smtp_exporter/internal/config"
)

// Build constructs a *tls.Config from the on-disk schema. serverName is the
// fallback SNI value used when cfg.ServerName is empty (typically the host
// portion of the dial address). Returns nil only when no TLS is configured;
// callers using TLS should always treat a non-nil return.
//
// MinVersion is fixed at TLS 1.2.
func Build(cfg config.TLSConfig, serverName string) (*tls.Config, error) {
	out := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // schema-honored, operator opt-in
	}
	if cfg.ServerName != "" {
		out.ServerName = cfg.ServerName
	} else {
		out.ServerName = serverName
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) // #nosec G304 -- operator-supplied CA path
		if err != nil {
			return nil, fmt.Errorf("read ca_file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %q: no certificates parsed", cfg.CAFile)
		}
		out.RootCAs = pool
	}
	return out, nil
}
