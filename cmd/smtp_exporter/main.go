// Command smtp_exporter is a Prometheus blackbox-style exporter for mail flow.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
	"github.com/tonobo/smtp_exporter/internal/server"
)

func main() {
	os.Exit(run())
}

func run() int {
	configFile := flag.String("config.file", "smtp_exporter.yml", "Path to config file.")
	configCheck := flag.Bool("config.check", false, "Validate config and exit.")
	listenAddress := flag.String("web.listen-address", ":9125", "Address on which to expose metrics and web interface.")
	webConfigFile := flag.String("web.config.file", "",
		"Path to configuration that can enable TLS or authentication. See exporter-toolkit docs.")
	showVersion := flag.Bool("version", false, "Print version information and exit.")
	flag.Parse()

	if *showVersion {
		_, _ = io.WriteString(os.Stdout, version.Print("smtp_exporter")+"\n")
		return 0
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	logger.Info("starting smtp_exporter", "version", version.Info())

	if *webConfigFile == "" {
		logger.Warn("HTTP endpoints unauthenticated",
			"hint", "set --web.config.file to enable basic auth or mTLS via prometheus/exporter-toolkit",
			"affected_endpoints", "/-/reload, /probe, /metrics, /config")
	}

	sc := config.NewSafeConfig()
	if err := sc.Reload(*configFile); err != nil {
		logger.Error("config reload failed", "err", err)
		return 1
	}

	// Warn about InsecureSkipVerify active in any module — valid for testing only.
	for name, mod := range sc.Get().Modules {
		if mod.SMTP.TLSConfig.InsecureSkipVerify {
			logger.Warn("InsecureSkipVerify=true active in module config",
				"module", name, "side", "smtp",
				"advice", "valid for testing only — disables certificate validation")
		}
		if mod.IMAP.TLSConfig.InsecureSkipVerify {
			logger.Warn("InsecureSkipVerify=true active in module config",
				"module", name, "side", "imap",
				"advice", "valid for testing only — disables certificate validation")
		}
	}

	if *configCheck {
		logger.Info("config ok")
		return 0
	}

	reload := func() error { return sc.Reload(*configFile) }

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := reload(); err != nil {
				logger.Error("sighup reload failed", "err", err)
			} else {
				logger.Info("config reloaded via sighup")
			}
		}
	}()

	h := server.NewHandler(logger, sc, pdns.System(), reload, prometheus.DefaultRegisterer)
	mux := http.NewServeMux()
	h.Register(mux)

	// ReadHeaderTimeout: slowloris guard for management endpoints; well above any legitimate header arrival.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	shutdownCtx, stopShutdown := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopShutdown()
	go func() {
		<-shutdownCtx.Done()
		logger.Info("shutdown signal received, draining HTTP server", "timeout_seconds", 10)
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelDrain()
		if err := srv.Shutdown(drainCtx); err != nil {
			logger.Warn("graceful shutdown failed", "err", err)
		}
	}()

	addrs := []string{*listenAddress}
	systemd := false
	webCfg := &web.FlagConfig{
		WebListenAddresses: &addrs,
		WebSystemdSocket:   &systemd,
		WebConfigFile:      webConfigFile,
	}
	if err := web.ListenAndServe(srv, webCfg, logger); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("http server failed", "err", err)
		return 1
	}
	return 0
}
