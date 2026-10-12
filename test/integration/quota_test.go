package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/registry-pass/internal/quota"
)

const quotaGrants = `
templates: [{repos: "{name}/**", actions: [pull, push, delete]}]
catalog: [%s]
`

// quotaSetup runs registry-pass with the quota module and a Distribution
// v3 that sends it notifications.
func quotaSetup(t *testing.T, quotaYAML string, members ...*nip01.Event) (*pass, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if members == nil {
		now := time.Now().Add(-time.Minute)
		members = []*nip01.Event{
			authority.Member(30078, "member:", "alice", alice.Pub, "alive", now),
			authority.Member(30078, "member:", "bob", bob.Pub, "alive", now),
		}
	}
	p := startPass(t, passOpts{
		grants: fmt.Sprintf(quotaGrants, builder.Npub), members: members,
		registry: l.Addr().String(), quota: quotaYAML,
	})
	reg := serveRegistryV3(t, p, l)
	waitFor(t, 10*time.Second, p.app.Quota.Ready)
	return p, reg
}

// blobsOf lists an image's stored blobs (manifest, config, layers) and sizes.
func blobsOf(t *testing.T, img v1.Image) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	raw, _ := img.RawManifest()
	d, _ := img.Digest()
	out[d.String()] = int64(len(raw))
	cfg, _ := img.RawConfigFile()
	cd, _ := img.ConfigName()
	out[cd.String()] = int64(len(cfg))
	layers, _ := img.Layers()
	for _, l := range layers {
		ld, _ := l.Digest()
		size, _ := l.Size()
		out[ld.String()] = size
	}
	return out
}

func total(sets ...map[string]int64) int64 {
	all := map[string]int64{}
	for _, s := range sets {
		maps.Copy(all, s)
	}
	var n int64
	for _, v := range all {
		n += v
	}
	return n
}

func used(p *pass, ns string) int64 { return p.app.Quota.Usage(ns).Used }

// settle waits until the tracked usage of every namespace is want.
func settle(t *testing.T, p *pass, want map[string]int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		ok := p.app.Quota.Pending() == 0
		for ns, n := range want {
			ok = ok && used(p, ns) == n
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			got := map[string]int64{}
			for ns := range want {
				got[ns] = used(p, ns)
			}
			t.Fatalf("usage %v, want %v", got, want)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func deleteImage(t *testing.T, reg, repo string, img v1.Image, auth authn.Authenticator) error {
	d, _ := img.Digest()
	name := strings.SplitN(repo, ":", 2)[0]
	return remote.Delete(ref(t, reg, name+"@"+d.String()), remote.WithAuth(auth))
}

// tokenBody asks for a token and returns the granted actions on repo and
// the warnings.
func (p *pass) grantedOn(t *testing.T, auth *authn.Basic, repo string) (string, []string) {
	t.Helper()
	q := url.Values{"service": {service}, "scope": {"repository:" + repo + ":pull,push,delete"}}
	req, _ := http.NewRequest("GET", p.realm+"?"+q.Encode(), nil)
	req.SetBasicAuth(auth.Username, auth.Password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b struct {
		Token    string
		Warnings []string
	}
	json.NewDecoder(resp.Body).Decode(&b)
	parts := strings.Split(b.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("token request: %d", resp.StatusCode)
	}
	var c struct {
		Access []struct{ Actions []string }
	}
	data, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(data, &c)
	if len(c.Access) == 0 {
		return "", b.Warnings
	}
	return strings.Join(c.Access[0].Actions, ","), b.Warnings
}

// TestQuotaRefusesPushKeepsPullDelete: a namespace past its quota gets no
// push in new passes but keeps pull and delete; deleting manifests brings
// push back before any garbage collection (criteria 1 and 2).
func TestQuotaRefusesPushKeepsPullDelete(t *testing.T) {
	p, reg := quotaSetup(t, "default: 3MiB")
	auth := p.creds(alice)
	one, two := randomImage(t, 4), randomImage(t, 4) // ~2 MiB each

	if err := push(t, reg, "alice/app:v1", one, auth); err != nil {
		t.Fatal(err)
	}
	settle(t, p, map[string]int64{"alice": total(blobsOf(t, one))})
	// Under quota: this push is granted and overshoots.
	if err := push(t, reg, "alice/app:v2", two, auth); err != nil {
		t.Fatalf("push under quota: %v", err)
	}
	settle(t, p, map[string]int64{"alice": total(blobsOf(t, one), blobsOf(t, two))})

	acts, warns := p.grantedOn(t, auth, "alice/app")
	if acts != "delete,pull" {
		t.Fatalf("over quota granted %q", acts)
	}
	if len(warns) != 1 || !strings.HasPrefix(warns[0], "namespace alice: 4") || !strings.HasSuffix(warns[0], "of 3MiB used — push refused; delete images to free space") {
		t.Fatalf("warnings %v", warns)
	}
	mustDenied(t, "push over quota", push(t, reg, "alice/other:v1", randomImage(t, 1), p.creds(alice)))
	if _, err := pull(t, reg, "alice/app:v1", p.creds(alice)); err != nil {
		t.Fatalf("pull over quota: %v", err)
	}
	// bob's namespace is not affected.
	if err := push(t, reg, "bob/app:v1", randomImage(t, 1), p.creds(bob)); err != nil {
		t.Fatalf("other namespace: %v", err)
	}

	if err := deleteImage(t, reg, "alice/app", two, p.creds(alice)); err != nil {
		t.Fatalf("delete over quota: %v", err)
	}
	settle(t, p, map[string]int64{"alice": total(blobsOf(t, one))})
	if acts, warns := p.grantedOn(t, p.creds(alice), "alice/app"); acts != "delete,pull,push" || warns != nil {
		t.Fatalf("after delete: %q %v", acts, warns)
	}
	if err := push(t, reg, "alice/app:v3", randomImage(t, 1), p.creds(alice)); err != nil {
		t.Fatalf("push after delete: %v", err)
	}
}

// TestQuotaSharedBlobs: a blob shared by two repositories in a namespace
// counts once; in two namespaces it counts in each (criterion 3).
func TestQuotaSharedBlobs(t *testing.T) {
	p, reg := quotaSetup(t, "default: 1GiB")
	img := randomImage(t, 3)
	for _, r := range []string{"alice/a:v1", "alice/b:v1", "alice/b:latest"} {
		if err := push(t, reg, r, img, p.creds(alice)); err != nil {
			t.Fatal(err)
		}
	}
	if err := push(t, reg, "bob/a:v1", img, p.creds(bob)); err != nil {
		t.Fatal(err)
	}
	size := total(blobsOf(t, img))
	settle(t, p, map[string]int64{"alice": size, "bob": size})
	if u := p.app.Quota.Usage("alice"); u.Blobs != 5 { // manifest, config, 3 layers
		t.Fatalf("alice %+v", u)
	}
}

// TestQuotaUsageMatchesRebuild: after pushes, tag moves and deletes,
// /usage/<name> equals a full recount (criterion 4).
func TestQuotaUsageMatchesRebuild(t *testing.T) {
	p, reg := quotaSetup(t, "default: 1GiB")
	base := randomImage(t, 2)
	imgs := map[string]v1.Image{}
	steps := []struct{ op, repo string }{
		{"push", "alice/a:v1"}, {"push", "alice/a:v2"}, {"push", "alice/b:v1"}, {"push", "bob/x:v1"},
		{"push", "alice/a:v1"}, // the tag moves to a new image
		{"delete", "alice/a:v2"}, {"push", "bob/y/z:v1"}, {"delete", "bob/x:v1"}, {"push", "alice/b:v2"},
	}
	for i, s := range steps {
		k := p.creds(alice)
		if strings.HasPrefix(s.repo, "bob/") {
			k = p.creds(bob)
		}
		switch s.op {
		case "push":
			img := randomImage(t, 1+i%3)
			if i%2 == 0 {
				img = base
			}
			imgs[s.repo] = img
			if err := push(t, reg, s.repo, img, k); err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
		case "delete":
			if err := deleteImage(t, reg, s.repo, imgs[s.repo], k); err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			delete(imgs, s.repo)
		}
	}
	want := map[string]int64{}
	for _, ns := range []string{"alice", "bob"} {
		var sets []map[string]int64
		for r, img := range imgs {
			if strings.HasPrefix(r, ns+"/") {
				sets = append(sets, blobsOf(t, img))
			}
		}
		want[ns] = total(sets...)
	}
	settle(t, p, want)

	viaHTTP := func(ns string, k *authn.Basic) quota.Report {
		req, _ := http.NewRequest("GET", strings.TrimSuffix(p.realm, "/token")+"/usage/"+ns, nil)
		req.SetBasicAuth(k.Username, k.Password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("/usage/%s: %d %s", ns, resp.StatusCode, body)
		}
		var r quota.Report
		json.NewDecoder(resp.Body).Decode(&r)
		return r
	}
	before := map[string]quota.Report{"alice": viaHTTP("alice", p.creds(alice)), "bob": viaHTTP("bob", p.creds(builder))}
	sum, err := p.app.Quota.Rebuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for ns, r := range before {
		if got := sum.Namespaces[ns]; got.Used != r.Used || got.Blobs != r.Blobs || r.Quota != 1<<30 {
			t.Errorf("%s: /usage %+v, recount %+v", ns, r, got)
		}
	}
}

// TestQuotaStoreLostRebuilds: a restart keeps the counts, and a lost store
// is rebuilt to the same numbers (criterion 5).
func TestQuotaStoreLostRebuilds(t *testing.T) {
	p, reg := quotaSetup(t, "default: 1GiB")
	a, b := randomImage(t, 2), randomImage(t, 3)
	push(t, reg, "alice/a:v1", a, p.creds(alice))
	push(t, reg, "bob/b:v1", b, p.creds(bob))
	settle(t, p, map[string]int64{"alice": total(blobsOf(t, a)), "bob": total(blobsOf(t, b))})
	want := p.app.Quota.All()

	p.restart()
	if !p.app.Quota.Ready() || !maps.Equal(p.app.Quota.All(), want) {
		t.Fatalf("after restart %v, want %v", p.app.Quota.All(), want)
	}

	p.stop()
	if err := os.RemoveAll(filepath.Join(p.dir, "data")); err != nil {
		t.Fatal(err)
	}
	p.start()
	waitFor(t, 10*time.Second, p.app.Quota.Ready)
	if !maps.Equal(p.app.Quota.All(), want) {
		t.Fatalf("rebuilt %v, want %v", p.app.Quota.All(), want)
	}
}

// TestQuotaSignedRaise: an authority-signed quota raise takes effect at the
// next pass; one signed by another key is ignored (criterion 6).
func TestQuotaSignedRaise(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	membersAlice := authority.Member(30078, "member:", "alice", alice.Pub, "alive", now)
	p, reg := quotaSetup(t, "default: 1MiB", membersAlice)
	if err := push(t, reg, "alice/app:v1", randomImage(t, 4), p.creds(alice)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, func() bool { return used(p, "alice") >= 1<<20 })
	if acts, _ := p.grantedOn(t, p.creds(alice), "alice/app"); acts != "delete,pull" {
		t.Fatalf("over quota: %q", acts)
	}

	forged := mallory.Quota(30078, "quota:", "alice", "1GiB", time.Now())
	p.setMembers(membersAlice, forged)
	time.Sleep(1500 * time.Millisecond) // two poll intervals
	if acts, _ := p.grantedOn(t, p.creds(alice), "alice/app"); acts != "delete,pull" {
		t.Fatalf("a raise signed by another key was applied: %q", acts)
	}

	p.setMembers(membersAlice, forged, authority.Quota(30078, "quota:", "alice", "1GiB", time.Now()))
	waitFor(t, 10*time.Second, func() bool { return p.app.Quota.Usage("alice").Quota == 1<<30 })
	if acts, _ := p.grantedOn(t, p.creds(alice), "alice/app"); acts != "delete,pull,push" {
		t.Fatalf("authority raise not applied: %q", acts)
	}
	if err := push(t, reg, "alice/app:v2", randomImage(t, 1), p.creds(alice)); err != nil {
		t.Fatalf("push after raise: %v", err)
	}
}

// TestQuotaConfigReload: perName edits to the config file apply on reload.
func TestQuotaConfigReload(t *testing.T) {
	p, reg := quotaSetup(t, "default: 1MiB")
	push(t, reg, "alice/app:v1", randomImage(t, 4), p.creds(alice))
	waitFor(t, 15*time.Second, func() bool { return used(p, "alice") >= 1<<20 })
	data, _ := os.ReadFile(p.config)
	os.WriteFile(p.config, []byte(strings.Replace(string(data), "default: 1MiB", "default: 1MiB, perName: {alice: 1GiB}", 1)), 0o600)
	if err := p.app.ReloadQuota(); err != nil {
		t.Fatal(err)
	}
	if acts, _ := p.grantedOn(t, p.creds(alice), "alice/app"); acts != "delete,pull,push" {
		t.Fatalf("perName raise not applied: %q", acts)
	}
}

// TestQuotaOffKeepsV020Behaviour: without the module, no quota endpoint
// answers and a full namespace still pushes (criterion 7).
func TestQuotaOffKeepsV020Behaviour(t *testing.T) {
	p := startPass(t, passOpts{grants: fmt.Sprintf(quotaGrants, builder.Npub)})
	reg := startRegistryV3(t, p)
	if p.app.Quota != nil {
		t.Fatal("quota module built while off")
	}
	for range 3 {
		if err := push(t, reg, "alice/app:v1", randomImage(t, 4), p.creds(alice)); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/events", "/usage/alice", "/quota/rebuild"} {
		resp, err := http.Post(strings.TrimSuffix(p.realm, "/token")+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s: %d with the module off", path, resp.StatusCode)
		}
	}
}
