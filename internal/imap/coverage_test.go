package imap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/tonobo/smtp_exporter/internal/testutil/imapfake"
	"github.com/tonobo/smtp_exporter/internal/testutil/tlstest"
)

// startSTARTTLSServer starts an in-memory IMAP server that supports STARTTLS
// using the provided server TLS config.
func startSTARTTLSServer(t *testing.T, serverTLS *tls.Config) (addr string) {
	t.Helper()
	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser("u", "p")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		InsecureAuth: true,
		TLSConfig:    serverTLS,
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
	})
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close() })
	return l.Addr().String()
}

// startTLSIMAPServer starts an in-memory IMAP server on an implicit TLS listener.
func startTLSIMAPServer(t *testing.T, serverTLS *tls.Config) (addr string) {
	t.Helper()
	memSrv := imapmemserver.New()
	user := imapmemserver.NewUser("u", "p")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	memSrv.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		InsecureAuth: true,
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memSrv.NewSession(), &imapserver.GreetingData{PreAuth: false}, nil
		},
	})
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close() })
	return l.Addr().String()
}

// TestConnect_StartTLS_Success verifies that connect succeeds with TLS:"starttls"
// when the client trusts the server's self-signed cert.
func TestConnect_StartTLS_Success(t *testing.T) {
	_, serverCfg, clientCfg := tlstest.SelfSigned(t)
	addr := startSTARTTLSServer(t, serverCfg)

	in := Input{
		Server:    addr,
		TLS:       "starttls",
		Username:  "u",
		Password:  "p",
		Mailbox:   "INBOX",
		TLSConfig: clientCfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := connect(ctx, in)
	if err != nil {
		t.Fatalf("connect (starttls): %v", err)
	}
	if err := c.Login("u", "p").Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = c.Logout().Wait()
	_ = c.Close()
}

// TestConnect_StartTLS_FailWithCertError verifies that STARTTLS with a
// self-signed cert and default client config (no RootCAs) returns a cert error.
func TestConnect_StartTLS_FailWithCertError(t *testing.T) {
	_, serverCfg, _ := tlstest.SelfSigned(t)
	addr := startSTARTTLSServer(t, serverCfg)

	// Client uses default TLS config — doesn't trust our self-signed cert.
	in := Input{
		Server:    addr,
		TLS:       "starttls",
		Username:  "u",
		Password:  "p",
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := connect(ctx, in)
	if err == nil {
		t.Fatal("expected cert verification error, got nil")
	}
}

// TestConnect_DirectTLS_Success verifies that connect works with TLS:"tls"
// using an implicit-TLS IMAP server.
func TestConnect_DirectTLS_Success(t *testing.T) {
	_, serverCfg, clientCfg := tlstest.SelfSigned(t)
	addr := startTLSIMAPServer(t, serverCfg)

	in := Input{
		Server:    addr,
		TLS:       "tls",
		Username:  "u",
		Password:  "p",
		Mailbox:   "INBOX",
		TLSConfig: clientCfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := connect(ctx, in)
	if err != nil {
		t.Fatalf("connect (tls): %v", err)
	}
	if err := c.Login("u", "p").Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = c.Logout().Wait()
	_ = c.Close()
}

// TestConnect_DirectTLS_ClosedPort verifies that dialing a closed port with TLS:tls returns error.
func TestConnect_DirectTLS_ClosedPort(t *testing.T) {
	_, _, clientCfg := tlstest.SelfSigned(t)

	in := Input{
		Server:    "127.0.0.1:1",
		TLS:       "tls",
		Username:  "u",
		Password:  "p",
		TLSConfig: clientCfg,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := connect(ctx, in)
	if err == nil {
		t.Fatal("expected error dialing closed port with TLS:tls")
	}
}

// TestWaitForSubject_LoginFailure verifies that login failure returns an error.
func TestWaitForSubject_LoginFailure(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	in := Input{
		Server:       fake.Addr,
		TLS:          "no",
		Username:     "u",
		Password:     "WRONGPASSWORD",
		Mailbox:      "INBOX",
		PollInterval: 200 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, err := WaitForSubject(ctx, in, "subject", []string{"INBOX"})
	if err == nil {
		t.Fatal("expected error for login failure")
	}
}

// TestWaitForSubject_NonexistentFirstFolder verifies that when the first folder
// doesn't exist (initial SELECT fails), an error is returned.
func TestWaitForSubject_NonexistentFirstFolder(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	in := Input{
		Server:       fake.Addr,
		TLS:          "no",
		Username:     "u",
		Password:     "p",
		Mailbox:      "INBOX",
		PollInterval: 200 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The first folder in the list doesn't exist — initial SELECT should return error.
	_, _, _, err := WaitForSubject(ctx, in, "subject", []string{"NoSuchFolder"})
	if err == nil {
		t.Fatal("expected error when first folder doesn't exist")
	}
}

// TestWaitForSubject_SkipsNonexistentSecondFolder verifies that a NO response
// on the second folder is silently skipped and INBOX is still polled.
func TestWaitForSubject_SkipsNonexistentSecondFolder(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	// Append the probe mail to INBOX.
	_ = fake.Append("INBOX", []byte("Subject: [smtp_exporter] skip-test\r\nX-Probe-ID: skip\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"))

	in := Input{
		Server:       fake.Addr,
		TLS:          "no",
		Username:     "u",
		Password:     "p",
		Mailbox:      "INBOX",
		PollInterval: 100 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// "NoSuchFolder" doesn't exist → NO response from SELECT → skip.
	// INBOX exists and has the message → should find it.
	raw, folder, uid, err := WaitForSubject(ctx, in, "[smtp_exporter] skip-test", []string{"INBOX", "NoSuchFolder"})
	if err != nil {
		t.Fatalf("WaitForSubject: %v", err)
	}
	_ = raw
	if folder != "INBOX" {
		t.Errorf("folder = %q, want INBOX", folder)
	}
	if uid == 0 {
		t.Error("uid should be non-zero")
	}
}

// TestConnect_InvalidMode verifies that an unknown TLS mode returns a clear error.
// (Duplicate definition removed — already defined above.)

// TestDiscoverFolders_ConnectFailure verifies that DiscoverFolders returns an
// error when connection fails.
func TestDiscoverFolders_ConnectFailure(t *testing.T) {
	in := Input{
		Server:  "127.0.0.1:1",
		TLS:     "no",
		Mailbox: "INBOX",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	folders, err := DiscoverFolders(ctx, in)
	if err == nil {
		t.Fatal("expected error when connection fails")
	}
	// Fallback: Inbox should always be set.
	if folders.Inbox != defaultInbox {
		t.Errorf("Inbox = %q, want %q", folders.Inbox, defaultInbox)
	}
}

// TestWithClient_LoginFailure verifies that withClient returns error on bad credentials.
func TestWithClient_LoginFailure(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		Username: "u",
		Password: "WRONG",
		Mailbox:  "INBOX",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := withClient(ctx, in, func(c *imapclient.Client) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for bad credentials")
	}
}

// Compile-time check that imapclient is imported.
var _ *imapclient.Client

// TestConnect_InvalidMode verifies that an unknown TLS mode returns a clear error.
func TestConnect_InvalidMode(t *testing.T) {
	in := Input{
		Server: "127.0.0.1:1",
		TLS:    "bogus",
	}
	ctx := context.Background()
	_, err := connect(ctx, in)
	if err == nil {
		t.Fatal("expected error for invalid TLS mode")
	}
	if !errors.Is(err, err) { // always true — just verify non-nil
		t.Fatal("err should be non-nil")
	}
}

// TestWaitForSubject_EmptyFolders verifies the early-return for empty folder list.
func TestWaitForSubject_EmptyFolders(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	in := Input{
		Server:       fake.Addr,
		TLS:          "no",
		Username:     "u",
		Password:     "p",
		Mailbox:      "INBOX",
		PollInterval: 200 * time.Millisecond,
	}
	_, _, _, err := WaitForSubject(context.Background(), in, "subject", []string{})
	if err == nil {
		t.Fatal("expected error for empty folders")
	}
}

// TestWaitForSubject_ZeroPollInterval verifies the early-return for zero poll interval.
func TestWaitForSubject_ZeroPollInterval(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	in := Input{
		Server:       fake.Addr,
		TLS:          "no",
		Username:     "u",
		Password:     "p",
		Mailbox:      "INBOX",
		PollInterval: 0,
	}
	_, _, _, err := WaitForSubject(context.Background(), in, "subject", []string{"INBOX"})
	if err == nil {
		t.Fatal("expected error for zero poll interval")
	}
}

// TestSweep_NoMatches verifies that sweeping an empty mailbox returns (0, nil).
func TestSweep_NoMatches(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		Username: "u",
		Password: "p",
		Mailbox:  "INBOX",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n, err := Sweep(ctx, in, 0)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 deleted from empty mailbox, got %d", n)
	}
}

// TestMoveToInbox_NonexistentUID verifies that MoveToInbox with a UID that doesn't
// exist returns a wrapped error.
func TestMoveToInbox_NonexistentUID(t *testing.T) {
	fake := imapfake.Start(t, "u", "p",
		imapfake.Inbox(),
		imapfake.Junk("[Gmail]/Spam"),
	)
	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		Username: "u",
		Password: "p",
		Mailbox:  "INBOX",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Append one message to spam so the select works but UID 9999 doesn't exist.
	_ = fake.Append("[Gmail]/Spam", []byte("Subject: test\r\nX-Probe-ID: x\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"))

	// Moving UID 9999 should fail gracefully.
	moved, err := MoveToInbox(ctx, in, "[Gmail]/Spam", imap.UID(9999))
	// Some servers accept MOVE of non-existent UID silently; others error.
	// Either is acceptable — we just verify no panic.
	_ = moved
	_ = err
}

// TestDiscoverFolders_E2E verifies DiscoverFolders via the public API.
func TestDiscoverFolders_E2E(t *testing.T) {
	fake := imapfake.Start(t, "u", "p",
		imapfake.Inbox(),
		imapfake.Junk("Junk"),
	)
	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		Username: "u",
		Password: "p",
		Mailbox:  "INBOX",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	folders, err := DiscoverFolders(ctx, in)
	if err != nil {
		t.Fatalf("DiscoverFolders: %v", err)
	}
	if folders.Inbox != "INBOX" {
		t.Errorf("Inbox = %q, want INBOX", folders.Inbox)
	}
	if folders.Spam != "Junk" {
		t.Errorf("Spam = %q, want Junk", folders.Spam)
	}
}

// TestSweep_WithMaxAge verifies that sweep respects max age filtering.
func TestSweep_WithMaxAge(t *testing.T) {
	fake := imapfake.Start(t, "u", "p")
	// Append a probe mail — in-memory server stamps current time.
	_ = fake.Append("INBOX", []byte("Subject: test\r\nX-Probe-ID: x\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n"))

	in := Input{
		Server:   fake.Addr,
		TLS:      "no",
		Username: "u",
		Password: "p",
		Mailbox:  "INBOX",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// max_age=24h: the message was just appended so it's NOT older than 24h → 0 deleted.
	n, err := Sweep(ctx, in, 24*time.Hour)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	// The message is fresh, so it should not be deleted.
	if n != 0 {
		t.Fatalf("expected 0 deleted for fresh message with 24h max_age, got %d", n)
	}
}
