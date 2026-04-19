package mail

import (
	"net"
	"net/mail"
	"regexp"
	"strings"
)

// bracket IP: [1.2.3.4] or [IPv6:2001:db8::1]
var ipInBrackets = regexp.MustCompile(`\[(?:IPv6:)?([0-9a-fA-F:.]+)\]`)

// byHostRE matches the "by <host>" clause in a Received header.
var byHostRE = regexp.MustCompile(`(?i)\bby\s+([a-zA-Z0-9.-]+)`)

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
	m := byHostRE.FindStringSubmatch(received[0])
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ParseReceivedHeaders parses raw RFC-5322 bytes and returns the Received
// header slice. Returns nil on parse error.
func ParseReceivedHeaders(raw []byte) []string {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil
	}
	return msg.Header["Received"]
}

func isPrivateOrLocal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
