package membership

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip09"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip46/bunker"
	"github.com/ohstr/nmilat/nipLS"
	"github.com/ohstr/nmilat/relay/client"
)

// RelaySource subscribes to membership events on relays through an
// nmilat Pool. Nostr tag filters match exact values, so records are
// selected by kind and author here and by d prefix in the Store.
type RelaySource struct {
	URLs        []string
	Kind        int
	Authorities []string
	Deletions   bool
	Signer      client.Signer // nil reads anonymously
	RequireAuth bool          // fresh only when AUTH succeeded
	AuthWait    time.Duration
	Resync      time.Duration
	PageSize    int
	DedupeSize  int
	Log         *slog.Logger

	pool atomic.Pointer[client.Pool]
}

func (r *RelaySource) Name() string { return "relay:" + strings.Join(r.URLs, ",") }

// Filter returns the subscription filter.
func (r *RelaySource) Filter() *nip01.SubscriptionFilterGroup {
	kinds := []int{r.Kind}
	if r.Deletions {
		kinds = append(kinds, nip09.KindDeletion)
	}
	return nip01.NewSubscriptionFilterGroup(nip01.NewFilter().WithKinds(kinds...).WithAuthors(r.Authorities...))
}

func (r *RelaySource) Run(ctx context.Context, store *Store) error {
	logf := func(format string, args ...any) {
		if r.Log != nil {
			r.Log.Debug(fmt.Sprintf(format, args...), "source", "relay")
		}
	}
	pool, err := client.NewPool(client.PoolConfig{
		Filter:         r.Filter(),
		OnEvent:        func(_ *client.Connection, ev *nip01.Event) { store.Ingest(ev) },
		Signer:         r.Signer,
		AuthWait:       r.AuthWait,
		ResyncInterval: r.Resync,
		PageSize:       r.PageSize,
		Dedupe:         r.DedupeSize > 0,
		DedupeSize:     r.DedupeSize,
		Logf:           logf,
	})
	if err != nil {
		return err
	}
	r.pool.Store(pool)
	for _, u := range r.URLs {
		if err := pool.Add(ctx, u); err != nil {
			return err
		}
	}
	<-ctx.Done()
	pool.Wait()
	return nil
}

// RelayState is one relay's freshness, for metrics.
type RelayState struct {
	URL       string
	Connected bool
	LastEOSE  time.Time
	Closed    string
	AuthOK    bool
}

// States reports every relay's state.
func (r *RelaySource) States() []RelayState {
	pool := r.pool.Load()
	if pool == nil {
		return nil
	}
	var out []RelayState
	for _, st := range pool.Statuses() {
		rs := RelayState{URL: st.URL, Connected: st.Connected, LastEOSE: st.LastEOSE, Closed: st.Closed}
		if conn, err := pool.Conn(context.Background(), st.URL, 0); err == nil {
			rs.AuthOK = conn.AuthState() == client.AuthStateSucceeded
		}
		out = append(out, rs)
	}
	return out
}

// LastSync is the most recent complete sync of any relay that counts: one
// whose AUTH succeeded when RequireAuth is set.
func (r *RelaySource) LastSync() time.Time {
	var last time.Time
	for _, st := range r.States() {
		if r.RequireAuth && r.Signer != nil && !st.AuthOK {
			continue
		}
		if st.LastEOSE.After(last) {
			last = st.LastEOSE
		}
	}
	return last
}

// NewSigner opens the reader identity: a key file's nsec or hex, a
// bunker:// remote signer, or a bunker+unix:// local signer.
func NewSigner(ctx context.Context, keyMaterial, uri string, timeout time.Duration) (client.Signer, func(), error) {
	if keyMaterial != "" {
		k, err := nip46.NewLocalKey(strings.TrimSpace(keyMaterial))
		if err != nil {
			return nil, nil, fmt.Errorf("reader key: %w", err)
		}
		return k, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch {
	case strings.HasPrefix(uri, "bunker+unix://"):
		c, err := nipLS.Dial(ctx, uri)
		if err != nil {
			return nil, nil, fmt.Errorf("reader signer: %w", err)
		}
		return c, func() { c.Close() }, nil
	case strings.HasPrefix(uri, "bunker://"):
		c, err := bunker.Dial(ctx, uri, bunker.ClientOptions{Perms: "sign_event:22242"})
		if err != nil {
			return nil, nil, fmt.Errorf("reader signer: %w", err)
		}
		return c, func() { c.Close() }, nil
	}
	return nil, nil, fmt.Errorf("reader signer: unsupported URI")
}
