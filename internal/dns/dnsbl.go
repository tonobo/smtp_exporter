package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// DNSBLResult captures one zone lookup outcome.
type DNSBLResult struct {
	Zone     string
	IP       net.IP
	Listed   bool
	Duration time.Duration
	Err      error
	// ResponseCode is the raw A-record value returned by the DNSBL, empty
	// if the query returned NXDOMAIN. Useful for diagnosing rate-limit /
	// open-resolver responses (127.255.255.*) that superficially look
	// like listings.
	ResponseCode string
}

// QueryBlacklist looks up ip against every zone and returns a DNSBLResult per zone.
// A NXDOMAIN response means "not listed". A non-NXDOMAIN response is
// treated as listed only if the A-record value falls inside the real
// listing range (see isListedResponseCode). Return codes like
// 127.255.255.252/254/255 (open-resolver refusal, rate-limit, misuse)
// populate ResponseCode but leave Listed=false so a throttled resolver
// does not produce false-positive listing metrics.
func QueryBlacklist(ctx context.Context, r Resolver, ip net.IP, zones []string) []DNSBLResult {
	out := make([]DNSBLResult, 0, len(zones))
	rev := reverseIP(ip)
	for _, z := range zones {
		start := time.Now()
		name := rev + "." + z
		addrs, err := r.LookupHost(ctx, name)
		res := DNSBLResult{Zone: z, IP: ip, Duration: time.Since(start)}
		switch {
		case err == nil && len(addrs) > 0:
			res.ResponseCode = addrs[0]
			res.Listed = isListedResponseCode(net.ParseIP(addrs[0]))
		case errors.Is(err, ErrNXDomain):
			res.Listed = false
		case err != nil:
			res.Err = err
		}
		out = append(out, res)
	}
	return out
}

// isListedResponseCode reports whether a DNSBL A-record response
// indicates a real listing. Most DNSBLs use 127.0.0.2 through
// 127.0.0.11 inclusive to encode sub-list codes (SBL, CSS, XBL,
// PBL, etc). Values like 127.255.255.252/254/255 are return codes
// (open-resolver refusal, rate-limit, or misuse) and do NOT
// indicate a listing. 127.0.0.1 is reserved / test-record and also
// does not count as listed.
//
// Reference:
// https://www.spamhaus.org/blocklists/dnsbl-usage/return-codes/
func isListedResponseCode(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] != 127 || v4[1] != 0 || v4[2] != 0 {
		return false
	}
	return v4[3] >= 2 && v4[3] <= 11
}

const hexDigits = "0123456789abcdef"

func reverseIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	}
	// IPv6: expand to 32 nibbles reversed, dot-separated.
	full := ip.To16()
	if full == nil {
		return ""
	}
	buf := make([]byte, 0, 64)
	for i := len(full) - 1; i >= 0; i-- {
		b := full[i]
		buf = append(buf, hexDigits[b&0x0f], '.', hexDigits[b>>4], '.')
	}
	return string(buf[:len(buf)-1])
}
