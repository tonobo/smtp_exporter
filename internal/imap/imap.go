// Package imap implements the receive phase of a mailflow probe.
package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/tonobo/smtp_exporter/internal/config"
)

const defaultInbox = "INBOX"

// Folders holds the discovered mailbox names for a connected account.
// Empty string means the folder was not found on this server.
type Folders struct {
	Inbox string // always "INBOX"
	Spam  string // "" if not found — set by \Junk attr (preferred) or well-known name
}

// discoverFolders issues LIST "" "*" with RETURN SPECIAL-USE and categorizes
// mailboxes by the \Junk attribute first, then by well-known names. Returns
// empty strings for folders not present on this server.
func discoverFolders(c *imapclient.Client) (Folders, error) {
	var f Folders
	f.Inbox = defaultInbox

	mailboxes, err := c.List("", "*", &imap.ListOptions{ReturnSpecialUse: true}).Collect()
	if err != nil {
		return f, fmt.Errorf("imap list: %w", err)
	}

	// Attribute match wins over name match.
	for _, mb := range mailboxes {
		for _, attr := range mb.Attrs {
			if attr == imap.MailboxAttrJunk {
				f.Spam = mb.Mailbox // \Junk attribute: Spam points to where spam lives
			}
		}
	}
	if f.Spam != "" {
		return f, nil
	}

	// Fallback: well-known names (case-insensitive).
	wellKnown := []string{"[Gmail]/Spam", "Spam", "Junk", "Junk Mail", "Junk E-mail"}
	for _, mb := range mailboxes {
		for _, wk := range wellKnown {
			if strings.EqualFold(mb.Mailbox, wk) {
				f.Spam = mb.Mailbox
				return f, nil
			}
		}
	}
	return f, nil
}

// Input describes an IMAP connection target.
type Input struct {
	Server       string // host:port
	TLS          string // starttls|tls|no
	Username     string
	Password     string
	Mailbox      string
	PollInterval time.Duration
	TLSConfig    *tls.Config
}

// DiscoverFolders connects to the IMAP server described by in, logs in, and
// returns the discovered folder layout. The connection is closed before return.
func DiscoverFolders(ctx context.Context, in Input) (Folders, error) {
	c, err := connect(ctx, in)
	if err != nil {
		return Folders{Inbox: defaultInbox}, err
	}
	defer func() {
		_ = c.Logout().Wait()
		_ = c.Close()
	}()

	if err := c.Login(in.Username, in.Password).Wait(); err != nil {
		return Folders{Inbox: "INBOX"}, fmt.Errorf("login: %w", err)
	}
	return discoverFolders(c)
}

// WaitForSubject polls the given folders every PollInterval until a message
// with the exact Subject header appears in one of them. It returns the raw
// RFC-5322 bytes of the message, the name of the folder where it was found,
// the UID of the found message, and any error. Folders are checked in order;
// the first match wins.
//
// A single-element slice []string{in.Mailbox} reproduces the original
// single-folder behaviour.
func WaitForSubject(ctx context.Context, in Input, subject string, folders []string) ([]byte, string, imap.UID, error) {
	if len(folders) == 0 {
		return nil, "", 0, errors.New("waitForSubject: no folders to poll")
	}
	if in.PollInterval <= 0 {
		return nil, "", 0, errors.New("waitForSubject: poll_interval must be positive")
	}

	c, err := connect(ctx, in)
	if err != nil {
		return nil, "", 0, err
	}
	defer func() {
		_ = c.Logout().Wait()
		_ = c.Close()
	}()

	if err := c.Login(in.Username, in.Password).Wait(); err != nil {
		return nil, "", 0, fmt.Errorf("login: %w", err)
	}

	// Select the first folder up-front to satisfy servers that require an
	// initial SELECT before issuing other commands.
	if _, err := c.Select(folders[0], &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return nil, "", 0, fmt.Errorf("select: %w", err)
	}

	for {
		for _, folder := range folders {
			// SELECT (read-only) switches to the folder and refreshes the view.
			if _, err := c.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
				// A NO response means the folder doesn't exist or we have no
				// permission — skip and try the next one. Any other error
				// (network, BAD response, etc.) is fatal.
				var imapErr *imap.Error
				if errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeNo {
					continue
				}
				return nil, "", 0, fmt.Errorf("select %s: %w", folder, err)
			}
			// NOOP causes the server to flush any pending untagged responses
			// (EXISTS, RECENT, etc.) so newly delivered messages become visible.
			// Most real IMAP servers (Gmail, Dovecot, Stalwart) require this.
			if err := c.Noop().Wait(); err != nil {
				return nil, "", 0, fmt.Errorf("noop: %w", err)
			}
			uids, err := searchSubject(c, subject)
			if err != nil {
				// A NO response from SEARCH means the folder has no permission
				// or the search failed softly — try next folder.
				var imapErr *imap.Error
				if errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeNo {
					continue
				}
				return nil, "", 0, fmt.Errorf("search %s: %w", folder, err)
			}
			if len(uids) > 0 {
				raw, fetchErr := fetchFirst(c, uids[0])
				return raw, folder, uids[0], fetchErr
			}
		}

		select {
		case <-ctx.Done():
			return nil, "", 0, fmt.Errorf("waitForSubject: %w", ctx.Err())
		case <-time.After(in.PollInterval):
		}
	}
}

// MoveToInbox moves a message from sourceFolder to INBOX, preferring IMAP
// MOVE (RFC 6851) and falling back to COPY + mark \Deleted + EXPUNGE.
// The go-imap/v2 client handles the fallback internally based on server caps.
// Returns (moved, error) — moved=true if the move completed successfully.
func MoveToInbox(ctx context.Context, in Input, sourceFolder string, uid imap.UID) (bool, error) {
	c, err := connect(ctx, in)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = c.Logout().Wait()
		_ = c.Close()
	}()

	if err := c.Login(in.Username, in.Password).Wait(); err != nil {
		return false, fmt.Errorf("login: %w", err)
	}

	// SELECT read-write (not ReadOnly) so MOVE / STORE \Deleted can proceed.
	if _, err := c.Select(sourceFolder, nil).Wait(); err != nil {
		return false, fmt.Errorf("select %q: %w", sourceFolder, err)
	}

	uidSet := imap.UIDSetNum(uid)
	if _, err := c.Move(uidSet, "INBOX").Wait(); err != nil {
		return false, fmt.Errorf("move uid %d from %q to INBOX: %w", uid, sourceFolder, err)
	}

	return true, nil
}

// Delete marks the given UIDs as \Deleted and expunges.
func Delete(ctx context.Context, in Input, uids []imap.UID) error {
	if len(uids) == 0 {
		return nil
	}
	c, err := connect(ctx, in)
	if err != nil {
		return err
	}
	defer func() {
		_ = c.Logout().Wait()
		_ = c.Close()
	}()
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

func connect(ctx context.Context, in Input) (*imapclient.Client, error) {
	d := &net.Dialer{}
	switch in.TLS {
	case "tls":
		cfg := in.TLSConfig
		if cfg == nil {
			cfg, _ = config.BuildTLSConfig(config.TLSConfig{}, config.HostOnly(in.Server))
		}
		cfg = ensureTLSMin(cfg)
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
			cfg, _ = config.BuildTLSConfig(config.TLSConfig{}, config.HostOnly(in.Server))
		}
		cfg = ensureTLSMin(cfg)
		c, err := imapclient.NewStartTLS(conn, &imapclient.Options{TLSConfig: cfg})
		if err != nil {
			_ = conn.Close()
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
	defer func() { _ = fc.Close() }()
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

func ensureTLSMin(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	if cfg.MinVersion == 0 {
		cfg = cfg.Clone()
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg
}

// Sweep deletes probe mails older than maxAge. A message is a "probe mail"
// if it has an X-Probe-ID header. maxAge <= 0 matches everything tagged.
func Sweep(ctx context.Context, in Input, maxAge time.Duration) (int, error) {
	c, err := connect(ctx, in)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = c.Logout().Wait()
		_ = c.Close()
	}()
	if err := c.Login(in.Username, in.Password).Wait(); err != nil {
		return 0, err
	}
	if _, err := c.Select(in.Mailbox, nil).Wait(); err != nil {
		return 0, err
	}

	crit := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "X-Probe-ID", Value: ""}},
	}
	if maxAge > 0 {
		crit.Before = time.Now().Add(-maxAge)
	}
	data, err := c.UIDSearch(crit, nil).Wait()
	if err != nil {
		return 0, err
	}
	uids := data.AllUIDs()
	if len(uids) == 0 {
		return 0, nil
	}
	set := imap.UIDSetNum(uids...)
	if err := c.Store(set, &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		return 0, err
	}
	if err := c.UIDExpunge(set).Close(); err != nil {
		return 0, err
	}
	return len(uids), nil
}
