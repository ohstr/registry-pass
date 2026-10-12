package quota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ohstr/registry-pass/internal/grants"
)

// fakeRegistry is a minimal registry API: catalog, tags, manifests and
// blob HEADs, paginated two items at a time.
type fakeRegistry struct {
	mu        sync.Mutex
	repos     map[string]*fakeRepo
	blobs     map[string]int64 // stored blobs by digest
	manifests map[string][]byte
	calls     int
}

type fakeRepo struct {
	tags      map[string]string // tag → manifest digest
	manifests map[string]bool   // digests present in the repository
	blobs     map[string]bool
}

func newFake() *fakeRegistry {
	return &fakeRegistry{repos: map[string]*fakeRepo{}, blobs: map[string]int64{}, manifests: map[string][]byte{}}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (f *fakeRegistry) repo(name string) *fakeRepo {
	r := f.repos[name]
	if r == nil {
		r = &fakeRepo{tags: map[string]string{}, manifests: map[string]bool{}, blobs: map[string]bool{}}
		f.repos[name] = r
	}
	return r
}

// blob makes a blob of size bytes, distinct per seed.
func blob(seed string, size int64) (string, int64) {
	return digestOf([]byte(fmt.Sprintf("blob:%s:%d", seed, size))), size
}

// pushImage stores an image manifest with a config and layers, tagged.
func (f *fakeRegistry) pushImage(repo, tag string, layers ...string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.repo(repo)
	type desc struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	var ls []desc
	for _, l := range layers {
		name, sizeStr, _ := strings.Cut(l, "=")
		size, _ := strconv.ParseInt(sizeStr, 10, 64)
		d, _ := blob(name, size)
		f.blobs[d] = size
		r.blobs[d] = true
		ls = append(ls, desc{"application/vnd.oci.image.layer.v1.tar+gzip", d, size})
	}
	cfg, _ := blob("config:"+strings.Join(layers, ","), 100)
	f.blobs[cfg] = 100
	r.blobs[cfg] = true
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": desc{"application/vnd.oci.image.config.v1+json", cfg, 100}, "layers": ls,
	})
	d := digestOf(body)
	f.manifests[d] = body
	r.manifests[d] = true
	if tag != "" {
		r.tags[tag] = d
	}
	return d
}

// pushIndex tags an index of manifests already in the repository.
func (f *fakeRegistry) pushIndex(repo, tag string, children ...string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.repo(repo)
	var ms []map[string]any
	for _, c := range children {
		ms = append(ms, map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": c, "size": len(f.manifests[c])})
	}
	body, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": ms})
	d := digestOf(body)
	f.manifests[d] = body
	r.manifests[d] = true
	r.tags[tag] = d
	return d
}

// deleteManifest removes a manifest and the tags pointing to it.
func (f *fakeRegistry) deleteManifest(repo, digest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.repo(repo)
	delete(r.manifests, digest)
	for t, d := range r.tags {
		if d == digest {
			delete(r.tags, t)
		}
	}
}

func (f *fakeRegistry) deleteTag(repo, tag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.repo(repo).tags, tag)
}

func page(items []string, q url.Values, path string, w http.ResponseWriter) []string {
	slices.Sort(items)
	n, _ := strconv.Atoi(q.Get("n"))
	if n <= 0 || n > 2 {
		n = 2
	}
	if last := q.Get("last"); last != "" {
		i, _ := slices.BinarySearch(items, last)
		for i < len(items) && items[i] <= last {
			i++
		}
		items = items[i:]
	}
	if len(items) > n {
		items = items[:n]
		w.Header().Set("Link", fmt.Sprintf(`<%s?n=%d&last=%s>; rel="next"`, path, n, url.QueryEscape(items[n-1])))
	}
	return items
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var access []grants.Access
	if err := json.Unmarshal([]byte(tok), &access); err != nil {
		http.Error(w, "no token", http.StatusUnauthorized)
		return
	}
	allowed := func(typ, name string) bool {
		for _, a := range access {
			if a.Type == typ && a.Name == name {
				return true
			}
		}
		return false
	}
	p := r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	if p == "/v2/_catalog" {
		if !allowed(grants.TypeRegistry, "catalog") {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		var names []string
		for n := range f.repos {
			names = append(names, n)
		}
		json.NewEncoder(w).Encode(map[string]any{"repositories": page(names, r.URL.Query(), p, w)})
		return
	}
	rest := strings.TrimPrefix(p, "/v2/")
	for _, kind := range []string{"/tags/list", "/manifests/", "/blobs/"} {
		i := strings.LastIndex(rest, kind)
		if i < 0 {
			continue
		}
		name, ref := rest[:i], rest[i+len(kind):]
		if !allowed(grants.TypeRepository, name) {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		repo := f.repos[name]
		if repo == nil {
			http.NotFound(w, r)
			return
		}
		switch kind {
		case "/tags/list":
			var tags []string
			for t := range repo.tags {
				tags = append(tags, t)
			}
			json.NewEncoder(w).Encode(map[string]any{"name": name, "tags": page(tags, r.URL.Query(), p, w)})
		case "/manifests/":
			d := ref
			if !strings.Contains(ref, ":") {
				d = repo.tags[ref]
			}
			if !repo.manifests[d] {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Docker-Content-Digest", d)
			w.Header().Set("Content-Length", strconv.Itoa(len(f.manifests[d])))
			if r.Method == http.MethodGet {
				w.Write(f.manifests[d])
			}
		case "/blobs/":
			if !repo.blobs[ref] {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Length", strconv.FormatInt(f.blobs[ref], 10))
		}
		return
	}
	http.NotFound(w, r)
}

// fakeMint encodes the access as the token, so the fake can check scopes.
func fakeMint(access []grants.Access) (string, error) {
	b, err := json.Marshal(access)
	return string(b), err
}

func startFake(t *testing.T) (*fakeRegistry, *Registry) {
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	return f, &Registry{Base: base, Client: srv.Client(), Mint: fakeMint}
}
