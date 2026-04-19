package dns

import (
	"context"
	"errors"
	"strings"
)

// SPFResult describes the outcome of an SPF lookup.
type SPFResult struct {
	Domain string
	Found  bool
	Record string
	Err    error
}

// LookupSPF returns the first TXT record that starts with "v=spf1".
func LookupSPF(ctx context.Context, r Resolver, domain string) SPFResult {
	out := SPFResult{Domain: domain}
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		if !errors.Is(err, ErrNXDomain) {
			out.Err = err
		}
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
