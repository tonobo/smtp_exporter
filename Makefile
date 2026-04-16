GO       ?= go
GOFLAGS  ?= -trimpath
PKG      := ./...
BIN      := smtp_exporter
VERSION  ?= $(shell git describe --tags --always --dirty)
LDFLAGS  := -s -w -X github.com/prometheus/common/version.Version=$(VERSION)

.PHONY: all build test test-cover lint vet tidy clean

all: build

build:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/smtp_exporter

test:
	$(GO) test $(PKG)

test-cover:
	$(GO) test -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -html=coverage.out -o coverage.html

vet:
	$(GO) vet $(PKG)

lint:
	golangci-lint run

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BIN) coverage.out coverage.html
