package dns

import (
	"context"
	"sync"
)

// Fake is an in-memory Resolver used by tests.
type Fake struct {
	mu   sync.RWMutex
	TXT  map[string][]string
	Host map[string][]string
	Addr map[string][]string
}

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{
		TXT:  make(map[string][]string),
		Host: make(map[string][]string),
		Addr: make(map[string][]string),
	}
}

// LookupTXT returns the configured TXT records for the given name.
func (f *Fake) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v, ok := f.TXT[name]
	if !ok {
		return nil, ErrNXDomain
	}
	return append([]string(nil), v...), nil
}

// LookupHost returns the configured addresses for the given host.
func (f *Fake) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v, ok := f.Host[host]
	if !ok {
		return nil, ErrNXDomain
	}
	return append([]string(nil), v...), nil
}

// LookupAddr returns the configured hostnames for the given address.
func (f *Fake) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v, ok := f.Addr[addr]
	if !ok {
		return nil, ErrNXDomain
	}
	return append([]string(nil), v...), nil
}
