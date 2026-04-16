// Command smtp_exporter is a Prometheus blackbox-style exporter for mail flow.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/tonobo/smtp_exporter/internal/config"
	pdns "github.com/tonobo/smtp_exporter/internal/dns"
	"github.com/tonobo/smtp_exporter/internal/server"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		configFile  = kingpin.Flag("config.file", "Path to config file.").Default("smtp_exporter.yml").String()
		configCheck = kingpin.Flag("config.check", "Validate config and exit.").Default("false").Bool()
		webCfg      = kingpinflag.AddFlags(kingpin.CommandLine, ":9125")
	)
	kingpin.Version(version.Print("smtp_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	logger.Info("starting smtp_exporter", "version", version.Info())

	sc := config.NewSafeConfig()
	if err := sc.Reload(*configFile); err != nil {
		logger.Error("config reload failed", "err", err)
		return 1
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

	h := server.NewHandler(sc, pdns.System(), reload, prometheus.DefaultRegisterer)
	mux := http.NewServeMux()
	h.Register(mux)

	srv := &http.Server{Handler: mux}
	if err := web.ListenAndServe(srv, webCfg, logger); err != nil && err != http.ErrServerClosed {
		logger.Error("http server failed", "err", err)
		fmt.Println(err)
		return 1
	}
	return 0
}
