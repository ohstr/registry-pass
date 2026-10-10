package testkit

import (
	"context"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nipLS"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/relay/client"
)

// StartRelay runs an embedded nmilat relay for the test and returns its
// ws:// URL. With authRequired, REQ and EVENT need NIP-42 AUTH.
func StartRelay(t testing.TB, authRequired bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws://" + ln.Addr().String()
	meta := &nip11.Metadata{
		Name: "test", URL: wsURL,
		Limitation: nip11.Limitation{MaxLimit: 1000, MaxMessageLength: 1 << 20, AuthRequired: authRequired},
	}
	rl, err := relay.New(filepath.Join(t.TempDir(), "relay.db"), meta)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(rl)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
		_ = rl.Close()
	})
	return wsURL
}

// Publish sends events to relayURL as k (authenticating if asked).
func Publish(t testing.TB, relayURL string, k Key, events ...*nip01.Event) {
	t.Helper()
	u, _ := url.Parse(relayURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.NewConnection(ctx, u, &client.ConnectionConfig{Signer: client.KeySigner(k.Priv)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-conn.AuthSettled():
	case <-time.After(500 * time.Millisecond): // open relays never challenge
	}
	for _, ev := range events {
		ok, err := conn.Publish(ctx, ev)
		if err != nil {
			t.Fatalf("publish: %v", err)
		}
		if ok != nil && !ok.Accepted {
			t.Fatalf("relay refused event: %s", ok.Message)
		}
	}
}

// StartSocketSigner serves k on a unix socket signer and returns its
// bunker+unix:// URI.
func StartSocketSigner(t testing.TB, k Key) string {
	t.Helper()
	key, err := nip46.NewLocalKey(k.Priv)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := nipLS.NewServer(nipLS.ServerConfig{Key: key, Policy: nipLS.AllowAll})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(shortTempDir(t), "s.sock")
	l, err := nipLS.Listen(path, nipLS.ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	return nipLS.FormatURI(path)
}

// shortTempDir keeps unix socket paths under the 108-byte limit.
func shortTempDir(t testing.TB) string {
	dir, err := os.MkdirTemp("", "rp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
