// Package config defines the on-disk configuration schema and loads it.
package config

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level config document.
type Config struct {
	Global  Global            `yaml:"global"`
	Modules map[string]Module `yaml:"modules"`
}

// Global holds settings that apply across all modules.
type Global struct {
	DNSBL   DNSBL   `yaml:"dnsbl"`
	Cleanup Cleanup `yaml:"cleanup"`
}

// DNSBL is the list of DNS blacklist zones to query.
type DNSBL struct {
	Zones []string `yaml:"zones"`
}

// Cleanup controls probe-mail housekeeping.
type Cleanup struct {
	Enabled bool          `yaml:"enabled"`
	MaxAge  time.Duration `yaml:"max_age"`
}

// Module is one prober configuration.
type Module struct {
	Prober  string        `yaml:"prober"`
	Timeout time.Duration `yaml:"timeout"`
	SMTP    SMTP          `yaml:"smtp"`
	IMAP    IMAP          `yaml:"imap"`
}

// SMTP is the SMTP-send portion of a module.
type SMTP struct {
	Server    string    `yaml:"server"`
	TLS       string    `yaml:"tls"` // starttls | tls | no
	EHLO      string    `yaml:"ehlo"`
	Auth      Auth      `yaml:"auth"`
	MailFrom  string    `yaml:"mail_from"`
	MailTo    string    `yaml:"mail_to"`
	TLSConfig TLSConfig `yaml:"tls_config"`
}

// IMAP is the IMAP-receive portion of a module.
type IMAP struct {
	Server       string        `yaml:"server"`
	TLS          string        `yaml:"tls"`
	Auth         Auth          `yaml:"auth"`
	Mailbox      string        `yaml:"mailbox"`
	PollInterval time.Duration `yaml:"poll_interval"`
	TLSConfig    TLSConfig     `yaml:"tls_config"`
}

// Auth holds simple username+password credentials.
type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// TLSConfig exposes a subset of crypto/tls.Config options.
type TLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	ServerName         string `yaml:"server_name"`
	CAFile             string `yaml:"ca_file"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	expanded := os.ExpandEnv(string(raw))
	var c Config
	if err := yaml.Unmarshal([]byte(expanded), &c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if len(c.Modules) == 0 {
		return fmt.Errorf("config: no modules defined")
	}
	for name, m := range c.Modules {
		if err := m.validate(); err != nil {
			return fmt.Errorf("module %q: %w", name, err)
		}
	}
	if c.Global.Cleanup.Enabled && c.Global.Cleanup.MaxAge <= 0 {
		return fmt.Errorf("global.cleanup.max_age must be positive when enabled")
	}
	return nil
}

func (m Module) validate() error {
	if m.Prober != "mailflow" {
		return fmt.Errorf("prober %q: only 'mailflow' is supported", m.Prober)
	}
	if m.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if err := validTLSMode(m.SMTP.TLS); err != nil {
		return fmt.Errorf("smtp.tls: %w", err)
	}
	if err := validTLSMode(m.IMAP.TLS); err != nil {
		return fmt.Errorf("imap.tls: %w", err)
	}
	if m.SMTP.Server == "" || m.SMTP.MailFrom == "" || m.SMTP.MailTo == "" {
		return fmt.Errorf("smtp: server, mail_from, and mail_to are required")
	}
	if m.IMAP.Server == "" || m.IMAP.Mailbox == "" {
		return fmt.Errorf("imap: server and mailbox are required")
	}
	return nil
}

func validTLSMode(v string) error {
	switch v {
	case "starttls", "tls", "no":
		return nil
	default:
		return fmt.Errorf("invalid mode %q (want starttls|tls|no)", v)
	}
}

// SafeConfig holds a Config that can be hot-reloaded.
type SafeConfig struct {
	v atomic.Pointer[Config]
}

// NewSafeConfig returns a SafeConfig with an empty Config set.
func NewSafeConfig() *SafeConfig {
	s := &SafeConfig{}
	s.v.Store(&Config{Modules: map[string]Module{}})
	return s
}

// Get returns the currently active Config (never nil).
func (s *SafeConfig) Get() *Config {
	return s.v.Load()
}

// Reload parses and validates the file; only swaps on success.
func (s *SafeConfig) Reload(path string) error {
	c, err := Load(path)
	if err != nil {
		return err
	}
	s.v.Store(c)
	return nil
}
