package message

import (
	"net"
	"net/mail"
	"regexp"
	"strings"
)

// bracket IP: [1.2.3.4] or [IPv6:2001:db8::1]
var ipInBrackets = regexp.MustCompile(`\[(?:IPv6:)?([0-9a-fA-F:.]+)\]`)

// FirstPublicSenderIP walks the Received: header chain from oldest to newest
// and returns the first IP literal that parses and is not in a private,
// loopback, link-local, or unspecified range.
func FirstPublicSenderIP(raw []byte) (net.IP, bool) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, false
	}
	received := msg.Header["Received"]
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

func isPrivateOrLocal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
