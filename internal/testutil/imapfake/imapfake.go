// Package imapfake spins up an in-memory IMAP server for tests.
//
// This package is internal test infrastructure. Its API is unstable
// and not covered by the project's semver promises — it may change
// or be removed at any time without notice.
package imapfake

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// Mailbox describes a mailbox to create at startup.
type Mailbox struct {
	Name       string
	SpecialUse []imap.MailboxAttr
}

// Inbox returns the conventional INBOX mailbox descriptor.
func Inbox() Mailbox { return Mailbox{Name: "INBOX"} }

// Junk returns a mailbox with the \Junk SPECIAL-USE attribute.
func Junk(name string) Mailbox {
	return Mailbox{Name: name, SpecialUse: []imap.MailboxAttr{imap.MailboxAttrJunk}}
}

// Fake is a running in-memory IMAP server.
type Fake struct {
	Addr string
	User *imapmemserver.User
	srv  *imapserver.Server
	l    net.Listener
}

// Start boots a fake IMAP server with the given user, password, and mailboxes.
// The server stops automatically when the test ends.
func Start(t *testing.T, username, password string, mailboxes ...Mailbox) *Fake {
	t.Helper()
	if len(mailboxes) == 0 {
		mailboxes = []Mailbox{Inbox()}
	}
	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser(username, password)
	for _, mb := range mailboxes {
		var opts *imap.CreateOptions
		if len(mb.SpecialUse) > 0 {
			opts = &imap.CreateOptions{SpecialUse: mb.SpecialUse}
		}
		if err := user.Create(mb.Name, opts); err != nil {
			t.Fatalf("imapfake: create %q: %v", mb.Name, err)
		}
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		InsecureAuth: true,
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
	})
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	if err != nil {
		t.Fatalf("imapfake: listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	f := &Fake{Addr: l.Addr().String(), User: user, srv: srv, l: l}
	t.Cleanup(f.stop)
	return f
}

// Append injects a raw RFC-5322 message into the named mailbox.
func (f *Fake) Append(mailbox string, raw []byte) error {
	_, err := f.User.Append(mailbox, &sizedReader{Reader: bytes.NewReader(raw), size: int64(len(raw))}, &imap.AppendOptions{Time: time.Now()})
	return err
}

func (f *Fake) stop() {
	_ = f.srv.Close()
	_ = f.l.Close()
}

// sizedReader implements imap.LiteralReader (io.Reader + Size).
type sizedReader struct {
	io.Reader
	size int64
}

func (r *sizedReader) Size() int64 { return r.size }
