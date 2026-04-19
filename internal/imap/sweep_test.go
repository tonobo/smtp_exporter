package imap

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSweep_DeletesOldProbeMail(t *testing.T) {
	addr, appendMsg, stop := startMemServer(t, "u", "p")
	defer stop()

	// Two probe mails. In-memory server stamps INTERNALDATE at Append time,
	// so we simulate age by passing maxAge=0, which matches everything tagged
	// with an X-Probe-ID header (regardless of how recent).
	for i := 0; i < 2; i++ {
		appendMsg([]byte(fmt.Sprintf("Subject: [smtp_exporter] p-%d\r\nX-Probe-ID: p-%d\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody\r\n", i, i)))
	}

	in := Input{Server: addr, TLS: "no", Username: "u", Password: "p", Mailbox: "INBOX", PollInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	n, err := Sweep(ctx, in, 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n < 2 {
		t.Fatalf("expected at least 2 deleted, got %d", n)
	}
}
