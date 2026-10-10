package membership

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/registry-pass/internal/testkit"
)

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func runRelaySource(t *testing.T, src *RelaySource, s *Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, s) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("relay source: %v", err)
		}
	})
}

func relaySource(url string, signer client.Signer) *RelaySource {
	return &RelaySource{
		URLs: []string{url}, Kind: kind, Authorities: []string{auth1.Pub}, Deletions: true,
		Signer: signer, RequireAuth: true, AuthWait: 2 * time.Second, Resync: time.Hour,
		PageSize: 2, DedupeSize: 1000,
	}
}

func TestRelaySourceWithAuth(t *testing.T) {
	url := testkit.StartRelay(t, true)
	now := time.Now()
	// More records than one page, plus noise the store must ignore.
	testkit.Publish(t, url, auth1,
		member(auth1, "alice", alice, "alive", now.Add(-3*time.Second)),
		member(auth1, "bob", bob, "alive", now.Add(-2*time.Second)),
		auth1.Sign(kind, now.Add(-time.Second), `{}`, []string{"d", "settings:x"}),
	)
	testkit.Publish(t, url, mallory, member(mallory, "mallory", mallory, "alive", now))

	s := liveStore()
	src := relaySource(url, client.KeySigner(testkit.NewKey("reader").Priv))
	s.AddSource(src)
	runRelaySource(t, src, s)

	waitFor(t, func() bool { return name(s, alice) == "alice" && name(s, bob) == "bob" })
	waitFor(t, s.Fresh)
	if name(s, mallory) != "" {
		t.Fatal("record by a non-authority accepted from the relay")
	}
	states := src.States()
	if len(states) != 1 || !states[0].AuthOK || states[0].LastEOSE.IsZero() {
		t.Fatalf("relay state %+v", states)
	}

	// A live revocation reaches the store without a resync.
	testkit.Publish(t, url, auth1, member(auth1, "alice", alice, "dead", now))
	waitFor(t, func() bool { return name(s, alice) == "" })
}

func TestRelaySourceWithoutReaderNeverFresh(t *testing.T) {
	url := testkit.StartRelay(t, true)
	testkit.Publish(t, url, auth1, member(auth1, "alice", alice, "alive", time.Now()))

	s := liveStore()
	src := relaySource(url, nil)
	s.AddSource(src)
	runRelaySource(t, src, s)

	time.Sleep(1500 * time.Millisecond)
	if s.Fresh() || name(s, alice) != "" {
		t.Fatal("an anonymous read of an AUTH-required relay counted as fresh")
	}
	st := src.States()
	if len(st) != 1 || !strings.Contains(st[0].Closed, "auth") {
		t.Fatalf("closed subscription not reported: %+v", st)
	}
}

func TestRelaySourceOpenRelayAndSocketSigner(t *testing.T) {
	url := testkit.StartRelay(t, false)
	testkit.Publish(t, url, auth1, member(auth1, "alice", alice, "alive", time.Now()))

	uri := testkit.StartSocketSigner(t, testkit.NewKey("reader"))
	signer, closeSigner, err := NewSigner(context.Background(), "", uri, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSigner()
	if signer.PubKey() != testkit.NewKey("reader").Pub {
		t.Fatal("socket signer pubkey")
	}

	s := liveStore()
	src := relaySource(url, nil)
	src.RequireAuth = false
	s.AddSource(src)
	runRelaySource(t, src, s)
	waitFor(t, func() bool { return name(s, alice) == "alice" && s.Fresh() })
}

func TestNewSigner(t *testing.T) {
	k := testkit.NewKey("reader")
	for _, material := range []string{k.Priv, k.Nsec, k.Nsec + "\n"} {
		s, closeFn, err := NewSigner(context.Background(), material, "", time.Second)
		if err != nil || s.PubKey() != k.Pub {
			t.Fatalf("key material %q: %v", material[:6], err)
		}
		closeFn()
	}
	for _, bad := range []string{"nope", k.Npub} {
		if _, _, err := NewSigner(context.Background(), bad, "", time.Second); err == nil {
			t.Errorf("key %q accepted", bad[:4])
		}
	}
	if _, _, err := NewSigner(context.Background(), "", "http://x", time.Second); err == nil {
		t.Fatal("unsupported URI accepted")
	}
	if _, _, err := NewSigner(context.Background(), "", "bunker+unix:///nonexistent/s.sock", time.Second); err == nil {
		t.Fatal("missing socket accepted")
	}
	if _, _, err := NewSigner(context.Background(), "", "bunker://"+k.Pub+"?relay=ws://127.0.0.1:1", 500*time.Millisecond); err == nil {
		t.Fatal("unreachable bunker accepted")
	}
}

func TestRelayFilterHasNoTagPrefix(t *testing.T) {
	f := relaySource("ws://x", nil).Filter().GetAll()[0]
	if len(f.Tags) != 0 {
		t.Fatal("tag filters match exact values only; the d prefix must be filtered locally")
	}
	if len(f.Kinds) != 2 || f.Authors[0] != auth1.Pub {
		t.Fatalf("filter %+v", f)
	}
	if (&RelaySource{}).States() != nil || !(&RelaySource{}).LastSync().IsZero() {
		t.Fatal("unstarted source")
	}
}
