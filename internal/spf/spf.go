// Package spf retrieves the SPF TXT record for a domain. It does not evaluate
// SPF — evaluation is the receiving MTA's job, and the result arrives via
// Authentication-Results.
package spf

import (
	"context"
	"strings"

	pdns "github.com/tonobo/smtp_exporter/internal/dns"
)

// Result describes the outcome of an SPF lookup.
type Result struct {
	Domain string
	Found  bool
	Record string
	Err    error
}

// Lookup returns the first TXT record that starts with "v=spf1".
func Lookup(ctx context.Context, r pdns.Resolver, domain string) Result {
	out := Result{Domain: domain}
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		out.Err = err
		return out
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			out.Found = true
			out.Record = t
			return out
		}
	}
	return out
}
