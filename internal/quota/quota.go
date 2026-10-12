// Package quota caps the storage of each top-level namespace: it counts
// what the registry holds from its notifications and a recount of its API,
// and tells the token endpoint which namespaces may not grow.
package quota

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/registry-pass/internal/bytesize"
	"github.com/ohstr/registry-pass/internal/grants"
)

// Limits are the configured quotas; they are swapped whole on reload.
type Limits struct {
	Default     int64
	PerName     map[string]int64
	ExemptNames map[string]bool
	ExemptKeys  map[string]bool // lowercase hex
}

// Options configure a Module.
type Options struct {
	Store    *Store
	Registry *Registry
	Limits   Limits
	// Signed returns the authority-signed quota of a namespace, if any.
	Signed func(name string) (int64, bool)
	// EventsToken authenticates the registry's notifications.
	EventsToken string
	// RebuildInterval is the time between full recounts; 0 = never.
	RebuildInterval time.Duration
	Log             *slog.Logger
	Now             func() time.Time
}

// Module tracks usage and decides whether a namespace may grow.
type Module struct {
	opts   Options
	store  *Store
	reg    *Registry
	limits atomic.Pointer[Limits]
	log    *slog.Logger

	repoLocks sync.Map // repository → *sync.Mutex
	rebuildMu sync.Mutex
	// touched collects the repositories recounted while a rebuild runs,
	// so one created after its catalog read is kept.
	touchMu sync.Mutex
	touched map[string]bool

	qmu     sync.Mutex
	queue   []string
	queued  map[string]bool
	busy    int
	wake    chan struct{}
	scanErr atomic.Int64
}

// New returns a Module; Run starts its worker.
func New(o Options) *Module {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Signed == nil {
		o.Signed = func(string) (int64, bool) { return 0, false }
	}
	m := &Module{opts: o, store: o.Store, reg: o.Registry, log: o.Log, queued: map[string]bool{}, wake: make(chan struct{}, 1)}
	m.SetLimits(o.Limits)
	return m
}

// SetLimits swaps in reloaded limits.
func (m *Module) SetLimits(l Limits) { m.limits.Store(&l) }

// Ready reports whether usage is known: a full rebuild has completed.
func (m *Module) Ready() bool { return !m.store.Rebuilt().IsZero() }

// Quota returns a namespace's quota in bytes; exempt reports no cap.
func (m *Module) Quota(name string) (quota int64, exempt bool) {
	l := m.limits.Load()
	if l.ExemptNames[name] {
		return 0, true
	}
	if q, ok := m.opts.Signed(name); ok {
		return q, false
	}
	if q, ok := l.PerName[name]; ok {
		return q, false
	}
	return l.Default, false
}

// Verdict is the quota decision for a push into one namespace.
type Verdict struct {
	Namespace string
	Used      int64
	Quota     int64
	// Refused is set when the namespace is at or over its quota.
	Refused bool
}

// Reason is the message that explains a refusal.
func (v Verdict) Reason() string {
	return fmt.Sprintf("namespace %s: %s of %s used — push refused; delete images to free space",
		v.Namespace, bytesize.Format(v.Used), bytesize.Format(v.Quota))
}

// CheckPush decides whether pubkey ("" for other subjects) may push into
// repo's namespace. Until usage is known, pushes are not capped.
func (m *Module) CheckPush(repo, pubkey string) Verdict {
	ns := Namespace(repo)
	v := Verdict{Namespace: ns}
	if pubkey != "" && m.limits.Load().ExemptKeys[pubkey] {
		return v
	}
	q, exempt := m.Quota(ns)
	if exempt || !m.Ready() {
		return v
	}
	v.Used, v.Quota = m.store.Usage(ns).Used, q
	v.Refused = v.Used >= v.Quota
	return v
}

// Filter removes push from every granted repository whose namespace is at
// or over its quota, and returns the refusals.
func (m *Module) Filter(access []grants.Access, pubkey string) ([]grants.Access, []Verdict) {
	var refused []Verdict
	seen := map[string]bool{}
	out := access[:0:0]
	for _, a := range access {
		if a.Type != grants.TypeRepository || !(slices.Contains(a.Actions, grants.ActionPush) || slices.Contains(a.Actions, grants.ActionAll)) {
			out = append(out, a)
			continue
		}
		v := m.CheckPush(a.Name, pubkey)
		if !v.Refused {
			out = append(out, a)
			continue
		}
		if !seen[v.Namespace] {
			seen[v.Namespace] = true
			refused = append(refused, v)
		}
		var acts []string
		for _, x := range a.Actions {
			switch x {
			case grants.ActionPush:
			case grants.ActionAll:
				// "*" without push: keep what the owner needs to clean up.
				for _, y := range []string{grants.ActionDelete, grants.ActionPull} {
					if !slices.Contains(acts, y) {
						acts = append(acts, y)
					}
				}
			default:
				if !slices.Contains(acts, x) {
					acts = append(acts, x)
				}
			}
		}
		slices.Sort(acts)
		if len(acts) > 0 {
			out = append(out, grants.Access{Type: a.Type, Name: a.Name, Actions: acts})
		}
	}
	return out, refused
}

// Report is what /usage/<name> returns.
type Report struct {
	Used   int64 `json:"used"`
	Quota  int64 `json:"quota"`
	Blobs  int   `json:"blobs"`
	Exempt bool  `json:"exempt,omitempty"`
}

// Usage reports a namespace's usage and quota.
func (m *Module) Usage(name string) Report {
	u := m.store.Usage(name)
	q, exempt := m.Quota(name)
	return Report{Used: u.Used, Quota: q, Blobs: u.Blobs, Exempt: exempt}
}

// All returns every namespace with stored content.
func (m *Module) All() map[string]Usage { return m.store.All() }

// Names lists the namespaces with stored content or a configured quota.
func (m *Module) Names() []string {
	set := map[string]bool{}
	for ns := range m.store.All() {
		set[ns] = true
	}
	for ns := range m.limits.Load().PerName {
		set[ns] = true
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	slices.Sort(out)
	return out
}

// CheckToken reports whether a bearer token is the events token.
func (m *Module) CheckToken(got string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(m.opts.EventsToken)) == 1
}

// maxEventsBody bounds one notification envelope.
const maxEventsBody = 8 << 20

// event is the part of a registry notification the tracker reads.
type event struct {
	Action string `json:"action"`
	Target struct {
		MediaType  string `json:"mediaType"`
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
		Tag        string `json:"tag"`
	} `json:"target"`
}

// Events reads a notification envelope and queues a recount of every
// repository whose manifests or tags changed. It returns how many
// repositories were queued.
func (m *Module) Events(r io.Reader) (int, error) {
	var env struct {
		Events []event `json:"events"`
	}
	dec := json.NewDecoder(io.LimitReader(r, maxEventsBody))
	if err := dec.Decode(&env); err != nil {
		return 0, fmt.Errorf("events: %w", err)
	}
	n := 0
	for _, ev := range env.Events {
		if !affectsUsage(ev) || !grants.ValidRepoName(ev.Target.Repository) {
			continue
		}
		if m.enqueue(ev.Target.Repository) {
			n++
		}
	}
	return n, nil
}

// affectsUsage reports whether an event can change what tags reach:
// manifest pushes and deletes, tag and repository deletes. Blob pushes,
// mounts and pulls can't.
func affectsUsage(ev event) bool {
	switch ev.Action {
	case "push":
		return slices.Contains(manifestTypes, ev.Target.MediaType)
	case "delete":
		return true
	}
	return false
}

func (m *Module) enqueue(repo string) bool {
	m.qmu.Lock()
	defer m.qmu.Unlock()
	if m.queued[repo] {
		return false
	}
	m.queued[repo] = true
	m.queue = append(m.queue, repo)
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return true
}

// Pending is how many repositories are queued or being recounted.
func (m *Module) Pending() int {
	m.qmu.Lock()
	defer m.qmu.Unlock()
	return len(m.queue) + m.busy
}

func (m *Module) next() (string, bool) {
	m.qmu.Lock()
	defer m.qmu.Unlock()
	if len(m.queue) == 0 {
		return "", false
	}
	repo := m.queue[0]
	m.queue = m.queue[1:]
	delete(m.queued, repo)
	m.busy++
	return repo, true
}

func (m *Module) done() {
	m.qmu.Lock()
	m.busy--
	m.qmu.Unlock()
}

// retryAfter is how long a failed recount waits before it runs again.
const retryAfter = 10 * time.Second

// Run recounts queued repositories, rebuilds when the store has never
// been rebuilt and every RebuildInterval, until ctx ends.
func (m *Module) Run(ctx context.Context) {
	go m.rebuilder(ctx)
	for {
		for {
			repo, ok := m.next()
			if !ok {
				break
			}
			if err := m.Rescan(ctx, repo); err != nil && ctx.Err() == nil {
				m.scanErr.Add(1)
				m.log.Warn("quota: recount failed; retrying", "repository", repo, "err", err)
				time.AfterFunc(retryAfter, func() { m.enqueue(repo) })
			}
			m.done()
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		}
	}
}

// Rebuild retries back off from minBackoff to maxBackoff.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
)

func (m *Module) rebuilder(ctx context.Context) {
	wait := time.Duration(0)
	if m.Ready() {
		wait = m.untilNext()
	}
	backoff := minBackoff
	for {
		if wait >= 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			if _, err := m.Rebuild(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				m.log.Error("quota: rebuild failed; retrying", "err", err, "in", backoff.String())
				wait, backoff = backoff, min(2*backoff, maxBackoff)
				continue
			}
			backoff = minBackoff
		}
		wait = m.untilNext()
		if wait < 0 {
			<-ctx.Done()
			return
		}
	}
}

// untilNext is the wait before the next periodic rebuild; -1 for none.
func (m *Module) untilNext() time.Duration {
	if m.opts.RebuildInterval <= 0 {
		return -1
	}
	return max(0, m.store.Rebuilt().Add(m.opts.RebuildInterval).Sub(m.opts.Now()))
}

// ScanErrors counts failed repository recounts.
func (m *Module) ScanErrors() int64 { return m.scanErr.Load() }

func (m *Module) lock(repo string) func() {
	v, _ := m.repoLocks.LoadOrStore(repo, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// Rescan recounts one repository from the registry.
func (m *Module) Rescan(ctx context.Context, repo string) error {
	unlock := m.lock(repo)
	defer unlock()
	blobs, err := m.walk(ctx, repo)
	if err != nil {
		return err
	}
	m.touchMu.Lock()
	if m.touched != nil {
		m.touched[repo] = true
	}
	m.touchMu.Unlock()
	return m.store.SetRepo(repo, blobs)
}

var (
	digestRe = regexp.MustCompile(`^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$`)
	tagRe    = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
)

// maxDepth bounds index nesting.
const maxDepth = 4

// walk returns every blob (manifests included) the repository's tags reach,
// with its size.
func (m *Module) walk(ctx context.Context, repo string) (map[string]int64, error) {
	tok, err := repoToken(m.reg.Mint, repo)
	if err != nil {
		return nil, err
	}
	tags, err := m.reg.Tags(ctx, repo, tok)
	if err != nil {
		return nil, err
	}
	blobs := map[string]int64{}
	for _, tag := range tags {
		if !tagRe.MatchString(tag) {
			continue
		}
		d, err := m.reg.Resolve(ctx, repo, tag, tok)
		if err != nil {
			return nil, err
		}
		if err := m.walkManifest(ctx, repo, d, tok, blobs, 0); err != nil {
			return nil, err
		}
	}
	return blobs, nil
}

func (m *Module) walkManifest(ctx context.Context, repo, digest, tok string, blobs map[string]int64, depth int) error {
	if !digestRe.MatchString(digest) || depth > maxDepth {
		return nil
	}
	if _, done := blobs[digest]; done {
		return nil
	}
	info, ok := m.store.manifest(digest)
	if !ok {
		body, err := m.reg.Manifest(ctx, repo, digest, tok)
		if err != nil || body == nil {
			return err
		}
		if info, err = parseManifest(body); err != nil {
			m.log.Warn("quota: unreadable manifest counted by its own size", "repository", repo, "digest", digest, "err", err)
			info = manifestInfo{Size: int64(len(body))}
		}
		if err := m.store.putManifest(digest, info); err != nil {
			return err
		}
	}
	blobs[digest] = info.Size
	for _, child := range info.Children {
		if err := m.walkManifest(ctx, repo, child, tok, blobs, depth+1); err != nil {
			return err
		}
	}
	for _, b := range info.Blobs {
		if !digestRe.MatchString(b) {
			continue
		}
		if _, done := blobs[b]; done {
			continue
		}
		size, ok := m.store.blobSize(b)
		if !ok {
			var found bool
			var err error
			if size, found, err = m.reg.BlobSize(ctx, repo, b, tok); err != nil {
				return err
			}
			if !found {
				continue // not stored here (a foreign layer, or missing)
			}
			if err := m.store.putBlobSize(b, size); err != nil {
				return err
			}
		}
		blobs[b] = size
	}
	return nil
}

// Summary is the result of a rebuild.
type Summary struct {
	Repositories int              `json:"repositories"`
	Namespaces   map[string]Usage `json:"namespaces"`
	Took         string           `json:"took"`
}

// rebuildWorkers is how many repositories a rebuild recounts at once.
const rebuildWorkers = 4

// Rebuild recounts every repository in the catalog and drops the ones
// that are gone. It is the source of truth.
func (m *Module) Rebuild(ctx context.Context) (Summary, error) {
	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()
	start := m.opts.Now()
	m.touchMu.Lock()
	m.touched = map[string]bool{}
	m.touchMu.Unlock()
	defer func() {
		m.touchMu.Lock()
		m.touched = nil
		m.touchMu.Unlock()
	}()
	repos, err := m.reg.Catalog(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("catalog: %w", err)
	}
	keep := map[string]bool{}
	work := make(chan string)
	errc := make(chan error, rebuildWorkers)
	var wg sync.WaitGroup
	for range rebuildWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repo := range work {
				if err := m.Rescan(ctx, repo); err != nil {
					errc <- fmt.Errorf("%s: %w", repo, err)
					return
				}
			}
		}()
	}
	var firstErr error
feed:
	for _, repo := range repos {
		if !grants.ValidRepoName(repo) {
			continue
		}
		keep[repo] = true
		select {
		case work <- repo:
		case firstErr = <-errc:
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr == nil {
		select {
		case firstErr = <-errc:
		default:
		}
	}
	if firstErr != nil {
		return Summary{}, firstErr
	}
	m.touchMu.Lock()
	for repo := range m.touched {
		keep[repo] = true
	}
	m.touchMu.Unlock()
	if err := m.store.finishRebuild(keep, m.opts.Now()); err != nil {
		return Summary{}, err
	}
	took := m.opts.Now().Sub(start).Round(time.Millisecond)
	all := m.store.All()
	m.log.Info("quota: rebuilt", "repositories", len(keep), "namespaces", len(all), "took", took.String())
	return Summary{Repositories: len(keep), Namespaces: all, Took: took.String()}, nil
}

// ErrNotReady is returned while usage is unknown.
var ErrNotReady = errors.New("quota usage is being rebuilt")
