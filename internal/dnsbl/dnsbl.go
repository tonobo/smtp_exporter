// Package dnsbl resolves DNS blacklist queries for a given IP.
package dnsbl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

// Result captures one zone lookup outcome.
type Result struct {
	Zone     string
	IP       net.IP
	Listed   bool
	Duration time.Duration
	Err      error
}

// Query looks up ip against every zone and returns a Result per zone.
// A NXDOMAIN response means "not listed"; any answer means listed.
func Query(ctx context.Context, r pdns.Resolver, ip net.IP, zones []string) []Result {
	out := make([]Result, 0, len(zones))
	rev := reverseIP(ip)
	for _, z := range zones {
		start := time.Now()
		name := rev + "." + z
		addrs, err := r.LookupHost(ctx, name)
		res := Result{Zone: z, IP: ip, Duration: time.Since(start)}
		switch {
		case err == nil && len(addrs) > 0:
			res.Listed = true
		case errors.Is(err, pdns.ErrNXDomain):
			res.Listed = false
		case err != nil:
			res.Err = err
		}
		out = append(out, res)
	}
	return out
}

func reverseIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	}
	// IPv6: expand to 32 nibbles reversed, dot-separated.
	full := ip.To16()
	if full == nil {
		return ""
	}
	nibbles := make([]string, 0, 32)
	for i := len(full) - 1; i >= 0; i-- {
		b := full[i]
		nibbles = append(nibbles, fmt.Sprintf("%x", b&0x0f))
		nibbles = append(nibbles, fmt.Sprintf("%x", b>>4))
	}
	return strings.Join(nibbles, ".")
}
