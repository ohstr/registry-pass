package quota

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/registry-pass/internal/grants"
)

func newModule(t *testing.T, reg *Registry, path string, l Limits) *Module {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "quota.db")
	}
	st, err := Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if l.Default == 0 {
		l.Default = 1 << 30
	}
	return New(Options{Store: st, Registry: reg, Limits: l, EventsToken: "tok"})
}

func rebuild(t *testing.T, m *Module) Summary {
	t.Helper()
	s, err := m.Rebuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSharedBlobs: a blob counts once per namespace and once in each
// namespace that uses it (criterion 3).
func TestSharedBlobs(t *testing.T) {
	f, reg := startFake(t)
	f.pushImage("alice/a", "v1", "base=1000", "app-a=10")
	f.pushImage("alice/b", "v1", "base=1000", "app-b=20")
	f.pushImage("alice/b", "v2", "base=1000", "app-b=20")
	f.pushImage("bob/c", "v1", "base=1000")
	m := newModule(t, reg, "", Limits{})
	rebuild(t, m)

	alice := m.Usage("alice")
	// base once, app-a, app-b once (v1 and v2 are one image), two configs,
	// two manifests.
	var manifests int64
	for _, repo := range []string{"alice/a", "alice/b"} {
		manifests += int64(len(f.manifests[f.repos[repo].tags["v1"]]))
	}
	if want := 1000 + 10 + 20 + 2*100 + manifests; alice.Used != want || alice.Blobs != 7 {
		t.Fatalf("alice %+v, want %d bytes in 7 blobs", alice, want)
	}
	base, _ := blob("base", 1000)
	shared := 0
	for repo, blobs := range m.store.repos {
		if strings.HasPrefix(repo, "alice/") {
			if _, ok := blobs[base]; ok {
				shared++
			}
		}
	}
	if shared != 2 {
		t.Fatalf("base not in both repositories: %d", shared)
	}
	if bob := m.Usage("bob"); bob.Used < 1000 {
		t.Fatalf("base not counted in bob: %+v", bob)
	}
	if got := sumDistinct(m, "alice"); got != alice.Used {
		t.Fatalf("alice used %d, distinct blobs sum to %d", alice.Used, got)
	}
}

func sumDistinct(m *Module, ns string) int64 {
	seen := map[string]int64{}
	for repo, blobs := range m.store.repos {
		if Namespace(repo) == ns {
			maps.Copy(seen, blobs)
		}
	}
	var n int64
	for _, s := range seen {
		n += s
	}
	return n
}

func TestIndexChildrenCounted(t *testing.T) {
	f, reg := startFake(t)
	amd := f.pushImage("alice/multi", "", "amd=500")
	arm := f.pushImage("alice/multi", "", "arm=700")
	f.pushIndex("alice/multi", "latest", amd, arm, "sha256:"+strings.Repeat("0", 64))
	m := newModule(t, reg, "", Limits{})
	rebuild(t, m)
	if u := m.Usage("alice"); u.Used < 1200 || u.Blobs != 7 { // index, 2 manifests, 2 configs, 2 layers
		t.Fatalf("index usage %+v", u)
	}
}

func TestUntaggedNotCounted(t *testing.T) {
	f, reg := startFake(t)
	f.pushImage("alice/x", "", "orphan=999")
	m := newModule(t, reg, "", Limits{})
	rebuild(t, m)
	if u := m.Usage("alice"); u.Used != 0 {
		t.Fatalf("untagged manifest counted: %+v", u)
	}
}

func events(repo string, actions ...string) string {
	var evs []string
	for _, a := range actions {
		action, mt, _ := strings.Cut(a, ":")
		evs = append(evs, fmt.Sprintf(`{"action":%q,"target":{"mediaType":%q,"repository":%q}}`, action, mt, repo))
	}
	return `{"events":[` + strings.Join(evs, ",") + `]}`
}

const ociManifest = "application/vnd.oci.image.manifest.v1+json"

func drain(t *testing.T, m *Module) {
	t.Helper()
	for {
		repo, ok := m.next()
		if !ok {
			return
		}
		if err := m.Rescan(context.Background(), repo); err != nil {
			t.Fatal(err)
		}
		m.done()
	}
}

func TestEventsQueueRecounts(t *testing.T) {
	f, reg := startFake(t)
	m := newModule(t, reg, "", Limits{})
	rebuild(t, m)

	f.pushImage("alice/app", "v1", "l=4096")
	n, err := m.Events(strings.NewReader(events("alice/app", "push:"+ociManifest, "push:"+ociManifest, "push:application/octet-stream", "pull:"+ociManifest, "mount:")))
	if err != nil || n != 1 {
		t.Fatalf("queued %d, %v; want one recount for repeated manifest pushes", n, err)
	}
	if m.Pending() != 1 {
		t.Fatalf("pending %d", m.Pending())
	}
	drain(t, m)
	if m.Usage("alice").Used < 4096 {
		t.Fatalf("push not counted: %+v", m.Usage("alice"))
	}
	f.deleteTag("alice/app", "v1")
	m.Events(strings.NewReader(events("alice/app", "delete:")))
	drain(t, m)
	if u := m.Usage("alice"); u.Used != 0 {
		t.Fatalf("deleted tag still counted: %+v", u)
	}
	for _, bad := range []string{"", "{", `{"events":[{"action":"push","target":{"mediaType":"` + ociManifest + `","repository":"../x"}}]}`} {
		if n, _ := m.Events(strings.NewReader(bad)); n != 0 {
			t.Errorf("%q queued %d", bad, n)
		}
	}
}

// TestTrackingMatchesRebuild: after a random sequence of pushes and
// deletes, the counts kept from events equal a full recount (criterion 4).
func TestTrackingMatchesRebuild(t *testing.T) {
	f, reg := startFake(t)
	m := newModule(t, reg, "", Limits{})
	rebuild(t, m)
	rnd := rand.New(rand.NewPCG(1, 2))
	repos := []string{"alice/a", "alice/b", "bob/a", "carol", "carol/x/y"}
	var pushed []struct{ repo, digest string }
	for i := range 200 {
		repo := repos[rnd.IntN(len(repos))]
		switch op := rnd.IntN(10); {
		case op < 5 || len(pushed) == 0:
			var layers []string
			for range 1 + rnd.IntN(3) {
				layers = append(layers, fmt.Sprintf("l%d=%d", rnd.IntN(15), 100+rnd.IntN(5000)))
			}
			d := f.pushImage(repo, fmt.Sprintf("t%d", rnd.IntN(4)), layers...)
			pushed = append(pushed, struct{ repo, digest string }{repo, d})
		case op < 8:
			p := pushed[rnd.IntN(len(pushed))]
			f.deleteManifest(p.repo, p.digest)
			repo = p.repo
		default:
			f.deleteTag(repo, fmt.Sprintf("t%d", rnd.IntN(4)))
		}
		m.Events(strings.NewReader(events(repo, "push:"+ociManifest)))
		if i%7 == 0 {
			drain(t, m)
		}
	}
	drain(t, m)
	tracked := m.All()
	if len(tracked) == 0 {
		t.Fatal("nothing tracked")
	}
	fresh := newModule(t, reg, "", Limits{})
	rebuild(t, fresh)
	if !maps.Equal(tracked, fresh.All()) {
		t.Fatalf("tracked %v\nrecount %v", tracked, fresh.All())
	}
	rebuild(t, m)
	if !maps.Equal(tracked, m.All()) {
		t.Fatalf("rebuild changed the tracked counts: %v → %v", tracked, m.All())
	}
}

// TestStoreSurvivesRestartAndLoss: the counts persist, and a lost store
// rebuilds to the same numbers (criterion 5).
func TestStoreSurvivesRestartAndLoss(t *testing.T) {
	f, reg := startFake(t)
	f.pushImage("alice/a", "v1", "x=3000", "y=10")
	f.pushImage("bob/a", "v1", "x=3000")
	path := filepath.Join(t.TempDir(), "data", "quota.db")
	st, err := Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := New(Options{Store: st, Registry: reg, Limits: Limits{Default: 1 << 30}})
	if m.Ready() {
		t.Fatal("a new store is ready before a rebuild")
	}
	rebuild(t, m)
	want := m.All()
	if _, err := Open(path, 50*time.Millisecond); err != ErrLocked {
		t.Fatalf("second open: %v, want ErrLocked", err)
	}
	st.Close()

	st, err = Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(st.All(), want) || st.Rebuilt().IsZero() {
		t.Fatalf("reopened %v, want %v", st.All(), want)
	}
	st.Close()

	os.Remove(path)
	st, err = Open(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m = New(Options{Store: st, Registry: reg, Limits: Limits{Default: 1 << 30}})
	if m.Ready() {
		t.Fatal("a lost store is ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for !m.Ready() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !maps.Equal(m.All(), want) {
		t.Fatalf("rebuilt %v, want %v", m.All(), want)
	}
}

func TestRebuildDropsGoneRepositoriesAndPrunes(t *testing.T) {
	f, reg := startFake(t)
	d := f.pushImage("alice/a", "v1", "x=10")
	m := newModule(t, reg, "", Limits{})
	rebuild(t, m)
	if _, ok := m.store.manifest(d); !ok {
		t.Fatal("manifest not cached")
	}
	delete(f.repos, "alice/a")
	rebuild(t, m)
	if len(m.All()) != 0 || len(m.store.Repos()) != 0 {
		t.Fatalf("gone repository still counted: %v", m.All())
	}
	if _, ok := m.store.manifest(d); ok {
		t.Fatal("cache not pruned")
	}
}

// TestRebuildKeepsRepositoriesRecountedMeanwhile: a repository created
// after the rebuild read the catalog, and recounted from its event, stays.
func TestRebuildKeepsRepositoriesRecountedMeanwhile(t *testing.T) {
	f, reg := startFake(t)
	f.pushImage("alice/a", "v1", "x=10")
	m := newModule(t, reg, "", Limits{})
	var fired atomic.Bool
	reg.Mint = func(access []grants.Access) (string, error) {
		// The catalog has been read: a push lands and its event is handled.
		if access[0].Type == grants.TypeRepository && fired.CompareAndSwap(false, true) {
			f.pushImage("carol/new", "v1", "y=20")
			if err := m.Rescan(context.Background(), "carol/new"); err != nil {
				t.Error(err)
			}
		}
		return fakeMint(access)
	}
	rebuild(t, m)
	if m.Usage("carol").Used == 0 {
		t.Fatal("a repository recounted during the rebuild was dropped")
	}
}

func TestCachesAvoidRefetching(t *testing.T) {
	f, reg := startFake(t)
	for i := range 3 {
		f.pushImage("alice/a", fmt.Sprintf("v%d", i), "base=100", fmt.Sprintf("l%d=10", i))
	}
	m := newModule(t, reg, "", Limits{})
	rebuild(t, m)
	f.calls = 0
	if err := m.Rescan(context.Background(), "alice/a"); err != nil {
		t.Fatal(err)
	}
	// tags (2 pages) + one HEAD per tag; no manifest or blob fetches.
	if f.calls != 2+3 {
		t.Fatalf("%d registry calls for a cached recount", f.calls)
	}
}

func TestQuotaPrecedenceAndFilter(t *testing.T) {
	f, reg := startFake(t)
	f.pushImage("alice/a", "v1", "x=5000")
	f.pushImage("bob/a", "v1", "x=5000")
	f.pushImage("ci/a", "v1", "x=5000")
	signed := map[string]int64{}
	m := newModule(t, reg, "", Limits{
		Default: 1000, PerName: map[string]int64{"bob": 1 << 20},
		ExemptNames: map[string]bool{"ci": true}, ExemptKeys: map[string]bool{"feed": true},
	})
	m.opts.Signed = func(n string) (int64, bool) { q, ok := signed[n]; return q, ok }

	req := []grants.Access{
		{Type: grants.TypeRepository, Name: "alice/a", Actions: []string{"delete", "pull", "push"}},
		{Type: grants.TypeRepository, Name: "alice/b", Actions: []string{"push"}},
		{Type: grants.TypeRepository, Name: "alice/c", Actions: []string{"*"}},
		{Type: grants.TypeRepository, Name: "bob/a", Actions: []string{"pull", "push"}},
		{Type: grants.TypeRepository, Name: "ci/a", Actions: []string{"push"}},
		{Type: grants.TypeRegistry, Name: "catalog", Actions: []string{"*"}},
	}
	// Not rebuilt yet: usage unknown, nothing capped.
	if got, refused := m.Filter(req, ""); len(refused) != 0 || len(got) != len(req) {
		t.Fatalf("capped before usage is known: %v", refused)
	}
	rebuild(t, m)
	got, refused := m.Filter(req, "")
	want := map[string]string{"alice/a": "delete,pull", "alice/c": "delete,pull", "bob/a": "pull,push", "ci/a": "push", "catalog": "*"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, a := range got {
		if strings.Join(a.Actions, ",") != want[a.Name] {
			t.Errorf("%s: %v, want %s", a.Name, a.Actions, want[a.Name])
		}
	}
	if len(refused) != 1 || refused[0].Namespace != "alice" {
		t.Fatalf("refused %v", refused)
	}
	msg := refused[0].Reason()
	if !strings.HasPrefix(msg, "namespace alice: ") || !strings.HasSuffix(msg, " of 1000B used — push refused; delete images to free space") {
		t.Fatalf("reason %q", msg)
	}
	if req[0].Actions[2] != "push" {
		t.Fatal("Filter changed its input")
	}
	// An exempt key pushes anywhere; a signed quota overrides the config.
	if _, refused := m.Filter(req, "feed"); len(refused) != 0 {
		t.Fatal("exempt key capped")
	}
	signed["alice"] = 1 << 30
	if _, refused := m.Filter(req, ""); len(refused) != 0 {
		t.Fatal("signed raise ignored")
	}
	signed["bob"] = 10
	if _, refused := m.Filter(req, ""); len(refused) != 1 || refused[0].Namespace != "bob" {
		t.Fatal("signed quota does not override perName")
	}
	if r := m.Usage("ci"); !r.Exempt || r.Used == 0 {
		t.Fatalf("exempt usage %+v", r)
	}
	if r := m.Usage("bob"); r.Quota != 10 || r.Blobs != 3 {
		t.Fatalf("bob usage %+v", r)
	}
}

func TestCheckToken(t *testing.T) {
	m := newModule(t, &Registry{Mint: fakeMint}, "", Limits{})
	if !m.CheckToken("tok") || m.CheckToken("") || m.CheckToken("tok2") {
		t.Fatal("token check")
	}
}

func TestRunRecountsAndRetries(t *testing.T) {
	f, reg := startFake(t)
	m := newModule(t, reg, "", Limits{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitUntil(t, m.Ready)
	f.pushImage("alice/a", "v1", "x=10")
	m.Events(strings.NewReader(events("alice/a", "push:"+ociManifest)))
	waitUntil(t, func() bool { return m.Usage("alice").Used > 0 && m.Pending() == 0 })
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestParseManifestAndLinks(t *testing.T) {
	info, err := parseManifest([]byte(`{"fsLayers":[{"blobSum":"sha256:a"},{"blobSum":"sha256:a"}]}`))
	if err != nil || len(info.Blobs) != 1 {
		t.Fatalf("schema1: %+v %v", info, err)
	}
	if _, err := parseManifest([]byte("nope")); err == nil {
		t.Fatal("bad manifest parsed")
	}
	if got := nextLink(`</v2/_catalog?n=2&last=b>; rel="next"`); got != "/v2/_catalog?n=2&last=b" {
		t.Fatal(got)
	}
	if nextLink(`</x>; rel="prev"`) != "" || nextLink("") != "" {
		t.Fatal("non-next link followed")
	}
}
