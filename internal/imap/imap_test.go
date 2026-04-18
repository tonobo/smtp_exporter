package imap

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
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
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
		InsecureAuth: true,
	})
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; context not meaningful for net.Listen
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()

	appendFn := func(raw []byte) {
		r := &sizedReader{strings.NewReader(string(raw)), int64(len(raw))}
		_, _ = user.Append("INBOX", r, &imap.AppendOptions{Time: time.Now()})
	}
	return l.Addr().String(), appendFn, func() { _ = srv.Close(); _ = l.Close() }
}

// memServerWithFolders starts an in-memory IMAP server pre-populated with the
// given mailbox names. Mailboxes listed in specialUseJunk will be created with
// the SPECIAL-USE \Junk attribute so that discoverFolders can detect them via
// attribute matching. The returned client is already logged in.
//
// Note: imapmemserver supports SPECIAL-USE via imap.CreateOptions{SpecialUse: ...}.
// The returned addr/client are wired through the standard mem-server pattern.
func memServerWithFolders(t *testing.T, mailboxes []string, specialUseJunk ...string) (addr string, stop func()) {
	t.Helper()
	junkSet := make(map[string]bool, len(specialUseJunk))
	for _, m := range specialUseJunk {
		junkSet[m] = true
	}

	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser("u", "p")
	for _, mb := range mailboxes {
		var opts *imap.CreateOptions
		if junkSet[mb] {
			opts = &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttrJunk}}
		}
		if err := user.Create(mb, opts); err != nil {
			t.Fatal(err)
		}
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
		InsecureAuth: true,
	})
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; context not meaningful for net.Listen
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String(), func() { _ = srv.Close(); _ = l.Close() }
}

// connectTest dials addr (plain TCP) and logs in as "u"/"p".
func connectTest(t *testing.T, addr string) *imapclient.Client {
	t.Helper()
	in := ClientInput{Server: addr, TLS: "no", Username: "u", Password: "p"}
	ctx := context.Background()
	c, err := connect(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login("u", "p").Wait(); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDiscoverFolders_GmailStyle verifies SPECIAL-USE \Junk attribute detection.
// The in-memory server supports SPECIAL-USE via imap.CreateOptions, so
// discoverFolders can match [Gmail]/Spam by attribute.
func TestDiscoverFolders_GmailStyle(t *testing.T) {
	addr, stop := memServerWithFolders(t,
		[]string{"INBOX", "[Gmail]/Spam", "[Gmail]/Sent Mail", "[Gmail]/Trash"},
		"[Gmail]/Spam", // SPECIAL-USE \Junk
	)
	defer stop()

	c := connectTest(t, addr)
	defer func() { _ = c.Logout() }()

	folders, err := discoverFolders(c)
	if err != nil {
		t.Fatalf("discoverFolders: %v", err)
	}
	if folders.Inbox != "INBOX" {
		t.Errorf("Inbox = %q, want INBOX", folders.Inbox)
	}
	if folders.Spam != "[Gmail]/Spam" {
		t.Errorf("Spam = %q, want [Gmail]/Spam", folders.Spam)
	}
}

// TestDiscoverFolders_DovecotStyle verifies well-known-name fallback detection.
// Note: If the in-memory server does not advertise SPECIAL-USE in its LIST
// response (e.g. because the library does not expose it via ReturnSpecialUse),
// discoverFolders falls back to matching by well-known name ("Junk"). This test
// deliberately does NOT pass Junk as a specialUseJunk folder, so it exercises
// the well-known-name path regardless of whether the server returns attributes.
func TestDiscoverFolders_DovecotStyle(t *testing.T) {
	addr, stop := memServerWithFolders(t,
		[]string{"INBOX", "Junk"},
		// No special-use attribute — relies on well-known-name fallback.
	)
	defer stop()

	c := connectTest(t, addr)
	defer func() { _ = c.Logout() }()

	folders, err := discoverFolders(c)
	if err != nil {
		t.Fatalf("discoverFolders: %v", err)
	}
	// Junk matches either via \Junk attribute or well-known name "Junk".
	if folders.Spam != "Junk" {
		t.Errorf("Spam = %q, want Junk", folders.Spam)
	}
}

func TestWaitForSubject_Found(t *testing.T) {
	addr, appendMsg, stop := startMemServer(t, "u", "p")
	defer stop()

	appendMsg([]byte("Subject: [smtp_exporter] abc-123\r\nX-Probe-ID: abc-123\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"))

	in := ClientInput{Server: addr, TLS: "no", Username: "u", Password: "p", Mailbox: "INBOX", PollInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	raw, folder, uid, err := WaitForSubject(ctx, in, "[smtp_exporter] abc-123", []string{"INBOX"})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !strings.Contains(string(raw), "abc-123") {
		t.Fatalf("body missing id: %q", raw)
	}
	if folder != "INBOX" {
		t.Errorf("folder = %q, want INBOX", folder)
	}
	if uid == 0 {
		t.Errorf("uid = 0, want non-zero")
	}
}

func TestWaitForSubject_Timeout(t *testing.T) {
	addr, _, stop := startMemServer(t, "u", "p")
	defer stop()

	in := ClientInput{Server: addr, TLS: "no", Username: "u", Password: "p", Mailbox: "INBOX", PollInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	_, _, _, err := WaitForSubject(ctx, in, "not-there", []string{"INBOX"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// TestWaitForSubject_FoundInSpam verifies that WaitForSubject detects a message
// delivered to Spam rather than INBOX when both are in the folder list.
func TestWaitForSubject_FoundInSpam(t *testing.T) {
	// Use a richer helper so we can append directly into the Spam folder via the
	// mem-server user (bypasses the IMAP client APPEND wire format complexity).
	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser("u", "p")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	if err := user.Create("[Gmail]/Spam", &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttrJunk}}); err != nil {
		t.Fatal(err)
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
		InsecureAuth: true,
	})
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; context not meaningful for net.Listen
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close(); _ = l.Close() }()
	addr := l.Addr().String()

	subj := "[smtp_exporter] spam-detect-test"
	raw := "Subject: " + subj + "\r\nX-Probe-ID: spam-test\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"
	sr := &sizedReader{strings.NewReader(raw), int64(len(raw))}
	if _, err := user.Append("[Gmail]/Spam", sr, &imap.AppendOptions{Time: time.Now()}); err != nil {
		t.Fatal(err)
	}

	in := ClientInput{Server: addr, TLS: "no", Username: "u", Password: "p", Mailbox: "INBOX", PollInterval: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, folder, _, err := WaitForSubject(ctx, in, subj, []string{"INBOX", "[Gmail]/Spam"})
	if err != nil {
		t.Fatalf("WaitForSubject: %v", err)
	}
	if folder != "[Gmail]/Spam" {
		t.Errorf("folder = %q, want [Gmail]/Spam", folder)
	}
}

// noopCountingListener wraps a net.Listener and counts NOOP commands seen
// in client→server traffic on accepted connections. This lets us verify that
// WaitForSubject actually sends NOOP before each search iteration, regardless
// of whether the in-memory server needs it to refresh the UID set.
//
// Note: the imapmemserver used in tests refreshes the mailbox view eagerly
// (every UIDSearch sees newly appended messages without NOOP). This means
// the functional part of the test (message found within timeout) would pass
// even without the NOOP fix. The NOOP-count assertion is what makes this test
// fail before the fix and pass after — it directly verifies the production fix
// that real IMAP servers (Gmail, Dovecot, Stalwart) require.
type noopCountingListener struct {
	net.Listener
	noopCount *atomic.Int64
}

func (l *noopCountingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &noopCountingConn{Conn: conn, noopCount: l.noopCount}, nil
}

type noopCountingConn struct {
	net.Conn
	noopCount *atomic.Int64
}

func (c *noopCountingConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

// Read intercepts client→server bytes to count NOOP commands.
func (c *noopCountingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		s := string(b[:n])
		// IMAP NOOP lines look like: "A3 NOOP\r\n"
		for _, line := range strings.Split(s, "\n") {
			upper := strings.ToUpper(strings.TrimSpace(line))
			if strings.HasSuffix(upper, " NOOP") || upper == "NOOP" {
				c.noopCount.Add(1)
			}
		}
	}
	return n, err
}

// startMemServerWithNoopCount is like startMemServer but also returns a counter
// that tracks how many NOOP commands the client has sent to the server.
func startMemServerWithNoopCount(t *testing.T, username, password string) (
	addr string, appendMsg func([]byte), noopsSent func() int64, stop func(),
) {
	t.Helper()
	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser(username, password)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
		InsecureAuth: true,
	})

	rawL, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; context not meaningful for net.Listen
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int64
	l := &noopCountingListener{Listener: rawL, noopCount: &count}
	go func() { _ = srv.Serve(l) }()

	appendFn := func(raw []byte) {
		r := &sizedReader{strings.NewReader(string(raw)), int64(len(raw))}
		_, _ = user.Append("INBOX", r, &imap.AppendOptions{Time: time.Now()})
	}
	return l.Addr().String(), appendFn, func() int64 { return count.Load() }, func() {
		_ = srv.Close()
		_ = rawL.Close()
	}
}

// TestWaitForSubject_PostSelectDelivery verifies that WaitForSubject finds a
// message that is delivered AFTER the initial SELECT.
//
// Most real IMAP servers (Gmail, Dovecot, Stalwart) only update the SELECTed
// mailbox's UID set when the client sends an explicit interaction such as NOOP.
// Without NOOP, repeated UIDSearch calls only see UIDs known at SELECT time,
// so a probe mail delivered after SELECT is invisible for the entire poll window.
//
// The test has two assertions:
//  1. WaitForSubject finds the message within the timeout (functional).
//  2. At least one NOOP was sent per search poll (structural — proves the fix
//     is in place even if the in-memory server refreshes eagerly on its own).
func TestWaitForSubject_PostSelectDelivery(t *testing.T) {
	addr, appendMsg, noopsSent, stop := startMemServerWithNoopCount(t, "u", "p")
	defer stop()

	// Pre-populate an unrelated message so SELECT returns a non-empty mailbox.
	// This reproduces the production state where INBOX already has mail and
	// a newly delivered probe message arrives after SELECT.
	appendMsg([]byte("Subject: unrelated-pre-existing\r\nFrom: a@b\r\nTo: c@d\r\n\r\npre-existing body\r\n"))

	const awaitedSubject = "[smtp_exporter] post-select-delivery-test"
	const pollInterval = 150 * time.Millisecond

	in := ClientInput{
		Server:       addr,
		TLS:          "no",
		Username:     "u",
		Password:     "p",
		Mailbox:      "INBOX",
		PollInterval: pollInterval,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type result struct {
		raw []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, _, _, err := WaitForSubject(ctx, in, awaitedSubject, []string{"INBOX"})
		ch <- result{raw, err}
	}()

	// Wait two full poll cycles so WaitForSubject has definitely done at least
	// one SELECT + search before the message is appended. This ensures the
	// message truly arrives post-SELECT.
	time.Sleep(2 * pollInterval)

	appendMsg([]byte("Subject: " + awaitedSubject + "\r\nX-Probe-ID: post-select\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"))

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("WaitForSubject returned error: %v (message was appended post-SELECT — NOOP fix may be missing)", r.err)
		}
		if !strings.Contains(string(r.raw), awaitedSubject) {
			t.Fatalf("returned message doesn't contain expected subject: %q", r.raw)
		}
	case <-ctx.Done():
		t.Fatal("WaitForSubject timed out waiting for post-SELECT message — NOOP fix may be missing")
	}

	// Structural assertion: at least one NOOP must have been sent.
	// Even if the in-memory server refreshes the UID set without NOOP (it does),
	// production servers require it. The NOOP count verifies the fix is present.
	noops := noopsSent()
	if noops == 0 {
		t.Fatalf("no NOOP commands were sent; WaitForSubject must send NOOP before each UIDSearch to refresh the mailbox view on real servers")
	}
	t.Logf("NOOP commands sent: %d", noops)
}

// TestMoveToInbox_FromGmailSpam verifies that MoveToInbox moves a message from
// a spam folder to INBOX and that the source folder no longer contains it.
func TestMoveToInbox_FromGmailSpam(t *testing.T) {
	const spamFolder = "[Gmail]/Spam"

	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser("u", "p")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	if err := user.Create(spamFolder, &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttrJunk}}); err != nil {
		t.Fatal(err)
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
		InsecureAuth: true,
	})
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper; context not meaningful for net.Listen
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close(); _ = l.Close() }()
	addr := l.Addr().String()

	// Append a probe message directly to the spam folder.
	const subj = "[smtp_exporter] move-to-inbox-test"
	raw := "Subject: " + subj + "\r\nX-Probe-ID: move-test\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"
	sr := &sizedReader{strings.NewReader(raw), int64(len(raw))}
	if _, err := user.Append(spamFolder, sr, &imap.AppendOptions{Time: time.Now()}); err != nil {
		t.Fatalf("append to spam: %v", err)
	}

	// Fetch the UID of the message we just appended via WaitForSubject.
	in := ClientInput{Server: addr, TLS: "no", Username: "u", Password: "p", Mailbox: "INBOX", PollInterval: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, folder, uid, err := WaitForSubject(ctx, in, subj, []string{"INBOX", spamFolder})
	if err != nil {
		t.Fatalf("WaitForSubject: %v", err)
	}
	if folder != spamFolder {
		t.Fatalf("expected message in %q, found in %q", spamFolder, folder)
	}
	if uid == 0 {
		t.Fatal("got uid=0, expected non-zero")
	}

	// Move it to INBOX.
	moved, err := MoveToInbox(ctx, in, spamFolder, uid)
	if err != nil {
		t.Fatalf("MoveToInbox: %v", err)
	}
	if !moved {
		t.Fatal("MoveToInbox returned moved=false")
	}

	// Verify INBOX now has the message.
	c := connectTest(t, addr)
	defer func() { _ = c.Logout() }()

	if _, err := c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		t.Fatalf("select INBOX: %v", err)
	}
	inboxUIDs, err := searchSubject(c, subj)
	if err != nil {
		t.Fatalf("search INBOX: %v", err)
	}
	if len(inboxUIDs) == 0 {
		t.Fatal("message not found in INBOX after MoveToInbox")
	}

	// Verify spam folder no longer has the message.
	if _, err := c.Select(spamFolder, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		t.Fatalf("select spam: %v", err)
	}
	spamUIDs, err := searchSubject(c, subj)
	if err != nil {
		t.Fatalf("search spam: %v", err)
	}
	if len(spamUIDs) != 0 {
		t.Fatalf("message still in spam after MoveToInbox (uids: %v)", spamUIDs)
	}
}

// Ensure noopCountingConn satisfies io.ReadWriteCloser for the compiler.
var _ io.Reader = (*noopCountingConn)(nil)
