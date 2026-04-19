package config_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonobo/smtp_exporter/internal/config"
)

func TestBuildTLSConfig_DefaultsMinTLS12(t *testing.T) {
	out, err := config.BuildTLSConfig(config.TLSConfig{}, "host.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", out.MinVersion, tls.VersionTLS12)
	}
	if out.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

func TestBuildTLSConfig_ServerNameFallback(t *testing.T) {
	out, err := config.BuildTLSConfig(config.TLSConfig{}, "fallback.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ServerName != "fallback.example" {
		t.Errorf("ServerName = %q, want %q", out.ServerName, "fallback.example")
	}
}

func TestBuildTLSConfig_ServerNameOverride(t *testing.T) {
	out, err := config.BuildTLSConfig(config.TLSConfig{ServerName: "x.example"}, "fallback.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ServerName != "x.example" {
		t.Errorf("ServerName = %q, want %q", out.ServerName, "x.example")
	}
}

func TestBuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	out, err := config.BuildTLSConfig(config.TLSConfig{InsecureSkipVerify: true}, "host.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestBuildTLSConfig_CAFile_Loaded(t *testing.T) {
	pemBytes := selfSignedPEM(t)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}

	out, err := config.BuildTLSConfig(config.TLSConfig{CAFile: caPath}, "host.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.RootCAs == nil {
		t.Fatal("RootCAs should not be nil after loading ca_file")
	}
	// Verify the pool contains the cert by parsing it back and checking subjects.
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse self-signed cert: %v", err)
	}
	subjects := out.RootCAs.Subjects() //nolint:staticcheck // easiest way to introspect pool
	for _, s := range subjects {
		if string(s) == string(cert.RawSubject) {
			return // found
		}
	}
	t.Errorf("loaded RootCAs pool does not contain the expected certificate subject")
}

func TestBuildTLSConfig_CAFile_NotFound(t *testing.T) {
	_, err := config.BuildTLSConfig(config.TLSConfig{CAFile: "/nonexistent/ca.pem"}, "host.example")
	if err == nil {
		t.Fatal("expected error for non-existent ca_file, got nil")
	}
}

func TestBuildTLSConfig_CAFile_GarbagePEM(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(caPath, []byte("this is not a pem file"), 0o600); err != nil {
		t.Fatalf("write garbage ca file: %v", err)
	}

	_, err := config.BuildTLSConfig(config.TLSConfig{CAFile: caPath}, "host.example")
	if err == nil {
		t.Fatal("expected error for garbage PEM, got nil")
	}
}

// selfSignedPEM generates a self-signed CA certificate PEM at test time.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
