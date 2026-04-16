// Package imap implements the receive phase of a mailflow probe.
package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// ClientInput describes an IMAP connection target.
type ClientInput struct {
	Server       string // host:port
	TLS          string // starttls|tls|no
	Username     string
	Password     string
	Mailbox      string
	PollInterval time.Duration
	TLSConfig    *tls.Config
}

// WaitForSubject polls the given mailbox every PollInterval until a message
// with the exact Subject header appears, then returns its raw RFC-5322 bytes.
func WaitForSubject(ctx context.Context, in ClientInput, subject string) ([]byte, error) {
	c, err := connect(ctx, in)
	if err != nil {
		return nil, err
	}
	defer c.Logout()

	if err := c.Login(in.Username, in.Password).Wait(); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	if _, err := c.Select(in.Mailbox, nil).Wait(); err != nil {
		return nil, fmt.Errorf("select: %w", err)
	}

	for {
		uids, err := searchSubject(c, subject)
		if err != nil {
			return nil, err
		}
		if len(uids) > 0 {
			return fetchFirst(c, uids[0])
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waitForSubject: %w", ctx.Err())
		case <-time.After(in.PollInterval):
		}
	}
}

// Delete marks the given UIDs as \Deleted and expunges.
func Delete(ctx context.Context, in ClientInput, uids []imap.UID) error {
	if len(uids) == 0 {
		return nil
	}
	c, err := connect(ctx, in)
	if err != nil {
		return err
	}
	defer c.Logout()
	if err := c.Login(in.Username, in.Password).Wait(); err != nil {
		return err
	}
	if _, err := c.Select(in.Mailbox, nil).Wait(); err != nil {
		return err
	}
	set := imap.UIDSetNum(uids...)
	if err := c.Store(set, &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		return err
	}
	if err := c.UIDExpunge(set).Close(); err != nil {
		return err
	}
	return nil
}

func connect(ctx context.Context, in ClientInput) (*imapclient.Client, error) {
	d := &net.Dialer{}
	switch in.TLS {
	case "tls":
		cfg := in.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: hostOnly(in.Server)}
		}
		td := &tls.Dialer{NetDialer: d, Config: cfg}
		conn, err := td.DialContext(ctx, "tcp", in.Server)
		if err != nil {
			return nil, err
		}
		return imapclient.New(conn, nil), nil
	case "starttls":
		conn, err := d.DialContext(ctx, "tcp", in.Server)
		if err != nil {
			return nil, err
		}
		cfg := in.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: hostOnly(in.Server)}
		}
		c, err := imapclient.NewStartTLS(conn, &imapclient.Options{TLSConfig: cfg})
		if err != nil {
			return nil, fmt.Errorf("starttls: %w", err)
		}
		return c, nil
	case "no":
		conn, err := d.DialContext(ctx, "tcp", in.Server)
		if err != nil {
			return nil, err
		}
		return imapclient.New(conn, nil), nil
	default:
		return nil, fmt.Errorf("invalid tls mode %q", in.TLS)
	}
}

func searchSubject(c *imapclient.Client, subject string) ([]imap.UID, error) {
	data, err := c.UIDSearch(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: subject}},
	}, nil).Wait()
	if err != nil {
		return nil, err
	}
	return data.AllUIDs(), nil
}

func fetchFirst(c *imapclient.Client, uid imap.UID) ([]byte, error) {
	set := imap.UIDSetNum(uid)
	fc := c.Fetch(set, &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	})
	defer fc.Close()
	for {
		msg := fc.Next()
		if msg == nil {
			return nil, errors.New("imap: message vanished")
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if body, ok := item.(imapclient.FetchItemDataBodySection); ok {
				if body.Literal == nil {
					continue
				}
				b, err := io.ReadAll(body.Literal)
				return b, err
			}
		}
	}
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
