package imap

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// sizedReader is a minimal imap.LiteralReader implementation.
type sizedReader struct {
	*strings.Reader
	size int64
}

func (s *sizedReader) Size() int64 { return s.size }

// startMemServer boots an in-memory IMAP server with one user + INBOX.
func startMemServer(t *testing.T, username, password string) (addr string, appendMsg func([]byte), stop func()) {
	t.Helper()
	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser(username, password)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
		InsecureAuth: true,
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()

	appendFn := func(raw []byte) {
		r := &sizedReader{strings.NewReader(string(raw)), int64(len(raw))}
		_, _ = user.Append("INBOX", r, &imap.AppendOptions{Time: time.Now()})
	}
	return l.Addr().String(), appendFn, func() { _ = srv.Close(); l.Close() }
}

func TestWaitForSubject_Found(t *testing.T) {
	addr, appendMsg, stop := startMemServer(t, "u", "p")
	defer stop()

	appendMsg([]byte("Subject: [smtp_exporter] abc-123\r\nX-Probe-ID: abc-123\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"))

	in := ClientInput{Server: addr, TLS: "no", Username: "u", Password: "p", Mailbox: "INBOX", PollInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	raw, err := WaitForSubject(ctx, in, "[smtp_exporter] abc-123")
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !strings.Contains(string(raw), "abc-123") {
		t.Fatalf("body missing id: %q", raw)
	}
}

func TestWaitForSubject_Timeout(t *testing.T) {
	addr, _, stop := startMemServer(t, "u", "p")
	defer stop()

	in := ClientInput{Server: addr, TLS: "no", Username: "u", Password: "p", Mailbox: "INBOX", PollInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	_, err := WaitForSubject(ctx, in, "not-there")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
