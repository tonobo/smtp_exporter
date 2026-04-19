// Package tlstest generates self-signed TLS certificates for tests.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// SelfSigned generates an ECDSA P-256 self-signed certificate suitable for
// in-process TLS tests. Returns:
//   - pemBytes: the cert in PEM form (suitable for writing to disk and loading via CAFile)
//   - serverCfg: a *tls.Config with the cert+key as identity
//   - clientCfg: a *tls.Config with the cert in RootCAs
//
// Generation uses ECDSA P-256 instead of RSA-2048 — about 50× faster, plenty for test certs.
func SelfSigned(t *testing.T) (pemBytes []byte, serverCfg, clientCfg *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlstest: keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smtp_exporter test"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("tlstest: createcert: %v", err)
	}

	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("tlstest: parse cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)

	serverCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	clientCfg = &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	return
}
