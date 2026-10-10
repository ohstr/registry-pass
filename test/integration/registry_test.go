package integration

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/registry-pass/internal/testkit"
)

// TestMemberNamespace: an alive member pushes and pulls <name>/** and
// nothing else (acceptance criterion 1).
func TestMemberNamespace(t *testing.T) {
	p := startPass(t, passOpts{})
	reg := startRegistryV3(t, p)
	img := randomImage(t, 3)

	if err := push(t, reg, "alice/app:v1", img, p.creds(alice)); err != nil {
		t.Fatalf("member push to own namespace: %v", err)
	}
	got, err := pull(t, reg, "alice/app:v1", p.creds(alice))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := img.Digest()
	if d, _ := got.Digest(); d != want {
		t.Fatal("pulled a different image")
	}
	mustDenied(t, "push outside the namespace", push(t, reg, "bob/app:v1", img, p.creds(alice)))
	mustDenied(t, "push to a look-alike namespace", push(t, reg, "alice-evil/app:v1", img, p.creds(alice)))
	mustDenied(t, "push to the bare name", push(t, reg, "alice:v1", img, p.creds(alice)))
	mustDenied(t, "non-member push", push(t, reg, "bob/app:v1", img, p.creds(bob)))
	_, err = pull(t, reg, "alice/app:v1", p.creds(bob))
	mustDenied(t, "non-member pull", err)
	_, err = pull(t, reg, "alice/app:v1", authn.Anonymous)
	mustDenied(t, "anonymous pull of a private repo", err)
}

// TestOtherSubjects: identities, static users, anonymous and deny list
// (acceptance criterion 1).
func TestOtherSubjects(t *testing.T) {
	p := startPass(t, passOpts{})
	reg := startRegistryV3(t, p)
	img := randomImage(t, 1)

	if err := push(t, reg, "bodies/x:v1", img, p.creds(builder)); err != nil {
		t.Fatalf("identities grant: %v", err)
	}
	mustDenied(t, "identity outside its grant", push(t, reg, "builder/x:v1", img, p.creds(builder)))

	static := &authn.Basic{Username: "node-pull", Password: staticPassword}
	if _, err := pull(t, reg, "bodies/x:v1", static); err != nil {
		t.Fatalf("static user pull: %v", err)
	}
	mustDenied(t, "static user push", push(t, reg, "bodies/y:v1", img, static))
	mustDenied(t, "static user wrong password", push(t, reg, "bodies/y:v1", img, &authn.Basic{Username: "node-pull", Password: "guess"}))

	mustDenied(t, "builder push to public/", push(t, reg, "public/x:v1", img, p.creds(builder)))
	mustDenied(t, "anonymous push", push(t, reg, "public/x:v1", img, authn.Anonymous))

	mallorySelf := testkit.NewKey("mallory")
	mustDenied(t, "deny-listed key", push(t, reg, "mallory/x:v1", img, p.creds(mallorySelf)))
}

// TestRevocationMidSession: a member set to dead loses access at the next
// token, while still holding a valid login event (criterion 3).
func TestRevocationMidSession(t *testing.T) {
	p := startPass(t, passOpts{})
	reg := startRegistryV3(t, p)
	auth := p.creds(alice) // one login event for the whole session
	if err := push(t, reg, "alice/app:v1", randomImage(t, 1), auth); err != nil {
		t.Fatal(err)
	}
	p.setMembers(authority.Member(30078, "member:", "alice", alice.Pub, "dead", time.Now()))
	waitFor(t, 10*time.Second, func() bool { return p.app.Store.Lookup(alice.Pub).Name == "" })
	mustDenied(t, "push after revocation", push(t, reg, "alice/app:v2", randomImage(t, 1), auth))
	_, err := pull(t, reg, "alice/app:v1", auth)
	mustDenied(t, "pull after revocation", err)
}

// TestForgedAndReplayedMembership: a record not signed by an authority, and
// an older alive record replayed after a newer dead one, change nothing
// (criteria 2 and 3).
func TestForgedAndReplayedMembership(t *testing.T) {
	alive := authority.Member(30078, "member:", "alice", alice.Pub, "alive", time.Now().Add(-time.Hour))
	dead := authority.Member(30078, "member:", "alice", alice.Pub, "dead", time.Now().Add(-time.Minute))
	forged := mallory.Member(30078, "member:", "mallory", mallory.Pub, "alive", time.Now())
	impostor := mallory.Member(30078, "member:", "bob", bob.Pub, "alive", time.Now())
	impostor.PubKey = authority.Pub // claims to be the authority

	p := startPass(t, passOpts{members: []*nip01.Event{dead, forged, impostor}})
	reg := startRegistryV3(t, p)
	img := randomImage(t, 1)
	mustDenied(t, "forged membership", push(t, reg, "mallory/x:v1", img, p.creds(mallory)))
	mustDenied(t, "impostor authority", push(t, reg, "bob/x:v1", img, p.creds(bob)))
	mustDenied(t, "revoked member", push(t, reg, "alice/x:v1", img, p.creds(alice)))

	// A stale source now serves only the older alive record.
	p.setMembers(alive)
	time.Sleep(1500 * time.Millisecond) // two poll intervals
	mustDenied(t, "replayed alive record", push(t, reg, "alice/x:v1", img, p.creds(alice)))
}

// TestLongSessionManyRequests: a multi-layer push and pull make many token
// requests within one login event.
func TestLongSessionManyRequests(t *testing.T) {
	p := startPass(t, passOpts{})
	reg := startRegistryV3(t, p)
	auth := p.creds(alice)
	for i := range 3 {
		img := randomImage(t, 6)
		if err := push(t, reg, fmt.Sprintf("alice/multi:v%d", i), img, auth); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if _, err := pull(t, reg, "alice/multi:v2", auth); err != nil {
		t.Fatal(err)
	}
	// Cross-repository blob mount: needs pull on the source too.
	src, _ := pull(t, reg, "alice/multi:v1", auth)
	if err := remote.Write(ref(t, reg, "alice/copy:v1"), src, remote.WithAuth(auth)); err != nil {
		t.Fatalf("mount between own repositories: %v", err)
	}
}

// TestStaleMembershipKeepsStaticUsers: when the membership source stops
// syncing, members are denied after staleAfter while static users keep
// pulling (onStale: denyMembers).
func TestStaleMembershipKeepsStaticUsers(t *testing.T) {
	p := startPass(t, passOpts{env: []string{"REGISTRY_PASS_MEMBERSHIP__STALE_AFTER=3s"}})
	reg := startRegistryV3(t, p)
	img := randomImage(t, 1)
	if err := push(t, reg, "alice/app:v1", img, p.creds(alice)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p.members); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, func() bool { return !p.app.Store.Fresh() })
	mustDenied(t, "member push with a stale view", push(t, reg, "alice/app:v2", img, p.creds(alice)))
	if _, err := pull(t, reg, "alice/app:v1", &authn.Basic{Username: "node-pull", Password: staticPassword}); err != nil {
		t.Fatalf("static user must keep pulling: %v", err)
	}
}
