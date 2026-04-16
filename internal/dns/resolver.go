// Package dns provides a minimal DNS resolver abstraction so probers can be
// tested without hitting the network.
package dns

import (
	"context"
	"errors"
	"net"
)

// ErrNXDomain is returned when a name has no record of the requested type.
var ErrNXDomain = errors.New("dns: nxdomain")

// Resolver is the minimal interface used by probers.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// System returns a Resolver backed by net.DefaultResolver.
func System() Resolver { return &sysResolver{r: net.DefaultResolver} }

type sysResolver struct{ r *net.Resolver }

func (s *sysResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	out, err := s.r.LookupTXT(ctx, name)
	return out, mapErr(err)
}
func (s *sysResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	out, err := s.r.LookupHost(ctx, host)
	return out, mapErr(err)
}
func (s *sysResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	out, err := s.r.LookupAddr(ctx, addr)
	return out, mapErr(err)
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return ErrNXDomain
	}
	return err
}
