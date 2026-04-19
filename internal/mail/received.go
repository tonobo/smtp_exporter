package mail

import (
	"net"
	"regexp"
)

// bracket IP: [1.2.3.4] or [IPv6:2001:db8::1]
var ipInBrackets = regexp.MustCompile(`\[(?:IPv6:)?([0-9a-fA-F:.]+)\]`)

// byBracketRE matches "by [192.0.2.1]" or "by [IPv6:2001:db8::1]" (RFC 5321
// bracketed forms).
var byBracketRE = regexp.MustCompile(`(?i)\bby\s+\[(?:IPv6:)?([^\]]+)\]`)

// byHostRE matches the "by <host>" clause in a Received header. The pattern
// requires the host to start with an alphanumeric character (not a dot or
// hyphen) to avoid partial matches.
var byHostRE = regexp.MustCompile(`(?i)\bby\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`)

// FirstPublicSenderIP walks the Received: header chain from oldest to newest
// and returns the first IP literal that parses and is not in a private,
// loopback, link-local, or unspecified range.
//
// received is the slice from msg.Header["Received"] — oldest entry is last
// (headers are prepended as mail flows). Pass nil/empty to get (nil, false).
func FirstPublicSenderIP(received []string) (net.IP, bool) {
	// Received headers are prepended as mail flows, so the oldest (most-external)
	// is last in the slice. Walk oldest → newest.
	for i := len(received) - 1; i >= 0; i-- {
		m := ipInBrackets.FindStringSubmatch(received[i])
		if m == nil {
			continue
		}
		ip := net.ParseIP(m[1])
		if ip == nil {
			continue
		}
		if isPrivateOrLocal(ip) {
			continue
		}
		return ip, true
	}
	return nil, false
}

// LastReceivingHost returns the hostname from the most recent (topmost)
// Received: header's "by <host>" clause. This identifies which receiving
// MX accepted the mail — useful when a domain has multiple MX records of
// equal priority and you want to monitor the load distribution.
//
// Caveat: some MTAs use generic names like "localhost.localdomain" or
// just "smtp" in the by clause; postfix/Stalwart/Exchange typically use
// the canonical FQDN.
func LastReceivingHost(received []string) (string, bool) {
	if len(received) == 0 {
		return "", false
	}
	// Try bracketed forms first: "by [192.0.2.1]" or "by [IPv6:2001:db8::1]".
	if m := byBracketRE.FindStringSubmatch(received[0]); m != nil {
		return m[1], true
	}
	// Fall back to bare FQDN / short name. Reject all-digit results, which
	// arise from Gmail's "by 2002:a05:6022:..." form where the IPv6 prefix
	// is not bracketed and the regex stops at the first colon.
	if m := byHostRE.FindStringSubmatch(received[0]); m != nil {
		host := m[1]
		if isAllDigits(host) {
			return "", false
		}
		return host, true
	}
	return "", false
}

// isAllDigits reports whether s is non-empty and contains only ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isPrivateOrLocal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
