# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags "-s -w -X github.com/prometheus/common/version.Version=${VERSION}" \
      -o /out/smtp_exporter ./cmd/smtp_exporter

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=build /out/smtp_exporter /smtp_exporter
EXPOSE 9125
ENTRYPOINT ["/smtp_exporter"]
