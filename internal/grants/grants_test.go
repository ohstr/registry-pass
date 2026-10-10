package grants

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/registry-pass/internal/testkit"
	"golang.org/x/crypto/bcrypt"
)

var (
	alice   = testkit.NewKey("alice")
	bob     = testkit.NewKey("bob")
	builder = testkit.NewKey("builder")
	mallory = testkit.NewKey("mallory")
	opts    = Options{NamePattern: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, AutoReserve: true}
)

func hash(t testing.TB, pw string, cost int) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func policy(t testing.TB, body string) *Policy {
	t.Helper()
	p, err := Parse([]byte(body), opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func fullPolicy(t testing.TB) *Policy {
	return policy(t, fmt.Sprintf(`
templates:
  - {repos: "{name}/**", actions: [pull, push]}
reservedNames: [admin]
anonymous:
  - {repos: "public/**", actions: [pull]}
identities:
  %q:
    - {repos: "bodies/**", actions: [pull, push]}
  %q:
    - {repos: "**", actions: [pull]}
staticUsers:
  node-pull:
    bcrypt: %q
    grants: [{repos: "**", actions: [pull]}]
catalog: [%q]
deny: [%q]
`, builder.Npub, bob.Pub, hash(t, "pull-secret", 10), bob.Npub, mallory.Npub))
}

func scopes(s ...string) []Scope { return ParseScopes(s) }

func access(typ, name string, acts ...string) Access {
	return Access{Type: typ, Name: name, Actions: acts}
}

func TestMemberGetsOnlyOwnNamespace(t *testing.T) {
	p := fullPolicy(t)
	alice := Subject{Pubkey: alice.Pub, MemberName: "alice"}
	cases := map[string][]Access{
		"repository:alice/app:pull,push":       {access("repository", "alice/app", "pull", "push")},
		"repository:alice/a/b/c:push":          {access("repository", "alice/a/b/c", "push")},
		"repository:alice:pull":                nil, // ** needs at least one segment
		"repository:alice-evil/app:pull,push":  nil, // prefix confusion
		"repository:alicex/app:pull":           nil,
		"repository:bob/app:pull":              nil,
		"repository:alice/app:delete":          nil, // not granted
		"repository:alice/app:*":               nil, // * only with *
		"repository:public/x:pull":             nil, // anonymous grants are for anonymous only
		"registry:catalog:*":                   nil,
		"repository:alice/../bob/app:pull":     nil, // traversal is not a valid name
		"repository:alice//app:pull":           nil,
		"repository:/alice/app:pull":           nil,
		"repository:alice/app/:pull":           nil,
		"repository:Alice/app:pull":            nil,
		"repository:alice/%2e%2e/bob:pull":     nil,
		"repository:alice/app:bob/app:pull":    nil, // colon smuggling
		"repository(plugin):alice/app:pull":    nil,
		"repository:alice/app:pull,admin,push": {access("repository", "alice/app", "pull", "push")},
	}
	for sc, want := range cases {
		got := p.Authorize(alice, scopes(sc))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", sc, got, want)
		}
	}
}

func TestPartialGrantsAcrossScopes(t *testing.T) {
	p := fullPolicy(t)
	got := p.Authorize(Subject{Pubkey: alice.Pub, MemberName: "alice"},
		scopes("repository:alice/app:pull,push repository:bob/lib:pull", "repository:alice/app:delete"))
	want := []Access{access("repository", "alice/app", "pull", "push")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestIdentitiesAndMembershipCombine(t *testing.T) {
	p := fullPolicy(t)
	// builder is not a member: only its identities grants.
	nonMember := Subject{Pubkey: builder.Pub}
	if got := p.Authorize(nonMember, scopes("repository:bodies/x:push")); len(got) != 1 {
		t.Fatalf("identities grant missing: %v", got)
	}
	if got := p.Authorize(nonMember, scopes("repository:builder/x:push")); got != nil {
		t.Fatalf("non-member got a template grant: %v", got)
	}
	// builder as a member gets both.
	member := Subject{Pubkey: builder.Pub, MemberName: "builder"}
	got := p.Authorize(member, scopes("repository:bodies/x:push", "repository:builder/x:push"))
	if len(got) != 2 {
		t.Fatalf("want both grants, got %v", got)
	}
	// bob reads everything, writes nothing, and may list the catalog.
	b := Subject{Pubkey: bob.Pub}
	got = p.Authorize(b, scopes("repository:anything/here:pull,push", "registry:catalog:*"))
	want := []Access{access("repository", "anything/here", "pull"), access("registry", "catalog", "*")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDenyWinsOverEverything(t *testing.T) {
	p := policy(t, fmt.Sprintf(`
templates: [{repos: "{name}/**", actions: [pull, push]}]
identities:
  %q: [{repos: "**", actions: ["*"]}]
catalog: [%q]
deny: [%q]
`, mallory.Npub, mallory.Pub, mallory.Pub))
	m := Subject{Pubkey: mallory.Pub, MemberName: "mallory"}
	if got := p.Authorize(m, scopes("repository:mallory/x:pull", "repository:any/x:pull", "registry:catalog:*")); got != nil {
		t.Fatalf("denied pubkey got %v", got)
	}
	if !p.Denied(mallory.Pub) || p.Denied(alice.Pub) {
		t.Fatal("Denied")
	}
}

func TestReservedNamesBlockNamespaceSquatting(t *testing.T) {
	p := fullPolicy(t)
	for _, name := range []string{"bodies", "admin", "public"} { // bodies & public auto-reserved
		s := Subject{Pubkey: alice.Pub, MemberName: name}
		if got := p.Authorize(s, scopes("repository:"+name+"/x:push")); got != nil {
			t.Errorf("member named %q got %v", name, got)
		}
	}
	for _, name := range []string{"Alice", "-alice", "alice-", "a/b", "**", "", strings.Repeat("a", 64)} {
		if p.ValidMemberName(name) {
			t.Errorf("name %q accepted", name)
		}
	}
	noAuto, err := Parse([]byte(`
templates: [{repos: "{name}/**", actions: [pull]}]
anonymous: [{repos: "public/**", actions: [pull]}]
`), Options{NamePattern: opts.NamePattern})
	if err != nil {
		t.Fatal(err)
	}
	if noAuto.Reserved("public") {
		t.Fatal("autoReserve off still reserved")
	}
}

func TestAnonymous(t *testing.T) {
	p := fullPolicy(t)
	anon := Subject{Anonymous: true}
	if got := p.Authorize(anon, scopes("repository:public/x:pull,push")); !reflect.DeepEqual(got, []Access{access("repository", "public/x", "pull")}) {
		t.Fatalf("got %v", got)
	}
	if got := p.Authorize(anon, scopes("repository:alice/x:pull")); got != nil {
		t.Fatalf("got %v", got)
	}
	empty := policy(t, "")
	if got := empty.Authorize(anon, scopes("repository:public/x:pull")); got != nil {
		t.Fatal("anonymous must get nothing by default")
	}
	if got := empty.Authorize(Subject{}, scopes("repository:public/x:pull")); got != nil {
		t.Fatal("empty subject must get nothing")
	}
}

func TestStaticUsers(t *testing.T) {
	p := fullPolicy(t)
	a := NewStaticAuth(time.Minute)
	if !p.IsStaticUser("node-pull") || p.IsStaticUser("nobody") {
		t.Fatal("IsStaticUser")
	}
	if !a.Check(p, "node-pull", "pull-secret") {
		t.Fatal("right password refused")
	}
	for _, pw := range []string{"", "wrong", "pull-secret ", strings.Repeat("x", 73), "pull-secret" + strings.Repeat("\x00", 70)} {
		if a.Check(p, "node-pull", pw) {
			t.Errorf("password %q accepted", pw)
		}
	}
	if a.Check(p, "nobody", "pull-secret") {
		t.Fatal("unknown user accepted")
	}
	got := p.Authorize(Subject{StaticUser: "node-pull"}, scopes("repository:any/x:pull,push,delete"))
	if !reflect.DeepEqual(got, []Access{access("repository", "any/x", "pull")}) {
		t.Fatalf("static pull user got %v", got)
	}
	if p.Authorize(Subject{StaticUser: "nobody"}, scopes("repository:any/x:pull")) != nil {
		t.Fatal("unknown static user got grants")
	}
}

func TestStaticAuthCache(t *testing.T) {
	p := fullPolicy(t)
	clock := time.Unix(1000, 0)
	a := NewStaticAuth(time.Minute)
	a.now = func() time.Time { return clock }
	if !a.Check(p, "node-pull", "pull-secret") || len(a.cache) != 1 {
		t.Fatal("success not cached")
	}
	if a.Check(p, "node-pull", "wrong") || len(a.cache) != 1 {
		t.Fatal("failure cached or accepted")
	}
	// A new grants file with a new password invalidates the cached success.
	p2 := policy(t, fmt.Sprintf("staticUsers:\n  node-pull:\n    bcrypt: %q\n", hash(t, "rotated", 10)))
	if a.Check(p2, "node-pull", "pull-secret") {
		t.Fatal("old password accepted after rotation via cache")
	}
	clock = clock.Add(2 * time.Minute)
	if !a.Check(p, "node-pull", "pull-secret") {
		t.Fatal("expired cache entry must fall back to bcrypt")
	}
	off := NewStaticAuth(0)
	off.Check(p, "node-pull", "pull-secret")
	if len(off.cache) != 0 {
		t.Fatal("ttl 0 cached")
	}
}

func TestInvalidGrantsFiles(t *testing.T) {
	cases := map[string]string{
		"unknown key":          "templats: []",
		"duplicate yaml key":   "deny: []\ndeny: []",
		"template no name":     `templates: [{repos: "shared/**", actions: [pull]}]`,
		"name in identities":   fmt.Sprintf("identities:\n  %q: [{repos: \"{name}/x\", actions: [pull]}]", alice.Npub),
		"bad action":           `anonymous: [{repos: "x", actions: [admin]}]`,
		"no actions":           `anonymous: [{repos: "x"}]`,
		"partial **":           `anonymous: [{repos: "a**", actions: [pull]}]`,
		"empty segment":        `anonymous: [{repos: "a//b", actions: [pull]}]`,
		"dot dot":              `anonymous: [{repos: "../x", actions: [pull]}]`,
		"uppercase":            `anonymous: [{repos: "Public/x", actions: [pull]}]`,
		"empty pattern":        `anonymous: [{repos: "", actions: [pull]}]`,
		"too many **":          `anonymous: [{repos: "**/a/**/b/**", actions: [pull]}]`,
		"nsec identity":        fmt.Sprintf("identities:\n  %q: [{repos: \"x\", actions: [pull]}]", alice.Nsec),
		"hex+npub same key":    fmt.Sprintf("identities:\n  %q: [{repos: \"x\", actions: [pull]}]\n  %q: [{repos: \"y\", actions: [pull]}]", alice.Npub, alice.Pub),
		"bad deny key":         "deny: [not-a-key]",
		"duplicate catalog":    fmt.Sprintf("catalog: [%q, %q]", alice.Npub, alice.Pub),
		"weak bcrypt":          fmt.Sprintf("staticUsers:\n  u:\n    bcrypt: %q", hash(t, "x", 4)),
		"plain password":       "staticUsers:\n  u:\n    bcrypt: hunter2",
		"user looks like npub": fmt.Sprintf("staticUsers:\n  %s:\n    bcrypt: %q", alice.Npub, hash(t, "x", 10)),
		"user looks like hex":  fmt.Sprintf("staticUsers:\n  %s:\n    bcrypt: %q", alice.Pub, hash(t, "x", 10)),
		"bad user name":        fmt.Sprintf("staticUsers:\n  \"a b\":\n    bcrypt: %q", hash(t, "x", 10)),
		"bad reserved name":    "reservedNames: [Admin]",
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body), opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(""), Options{NamePattern: "("}); err == nil {
		t.Error("bad name pattern accepted")
	}
	err := func() error { _, err := Parse([]byte("deny: [x]\ncatalog: [y]"), opts); return err }()
	if err == nil || !strings.Contains(err.Error(), "deny[0]") || !strings.Contains(err.Error(), "catalog[0]") {
		t.Fatalf("errors must list every problem: %v", err)
	}
}

func TestPatterns(t *testing.T) {
	cases := []struct {
		pat, repo, name string
		want            bool
	}{
		{"**", "a", "", true},
		{"**", "a/b/c", "", true},
		{"a/*", "a/b", "", true},
		{"a/*", "a/b/c", "", false},
		{"a/**/z", "a/b/c/z", "", true},
		{"a/**/z", "a/z", "", false},
		{"team-*/app", "team-red/app", "", true},
		{"team-*/app", "team-/app", "", true},
		{"team-*/app", "teams/app", "", false},
		{"*-svc", "api-svc", "", true},
		{"a*b*c", "abc", "", true},
		{"a*b*c", "axxbyyc", "", true},
		{"a*b*c", "acb", "", false},
		{"ab*ba", "aba", "", false},
		{"{name}/**", "alice/x", "alice", true},
		{"{name}/**", "alice/x", "", false},
		{"{name}/**", "bob/x", "alice", false},
		{"{name}", "alice", "alice", true},
	}
	for _, tc := range cases {
		p, err := ParsePattern(tc.pat, true)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Match(tc.repo, tc.name); got != tc.want {
			t.Errorf("%q ~ %q (name %q) = %v, want %v", tc.pat, tc.repo, tc.name, got, tc.want)
		}
	}
	if p, _ := ParsePattern("a/b", false); p.String() != "a/b" {
		t.Error("String")
	}
}

func TestParseScopes(t *testing.T) {
	got := ParseScopes([]string{"repository:a/b:pull repository:a/b:push,pull", "registry:catalog:*", "registry:other:*", "garbage", "repository:a:"})
	want := []Scope{
		{Type: "repository", Name: "a/b", Actions: []string{"pull", "push"}},
		{Type: "registry", Name: "catalog", Actions: []string{"*"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if ValidRepoName(strings.Repeat("a", 256)) || !ValidRepoName(strings.Repeat("a", 255)) {
		t.Fatal("length limit")
	}
	for _, ok := range []string{"a", "a/b", "a.b", "a_b", "a__b", "a--b", "0"} {
		if !ValidRepoName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "A", "a/", "/a", "a//b", "a..b", ".a", "a_", "a___b", "a:b", "a b", "é"} {
		if ValidRepoName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestExampleGrantsAreValid(t *testing.T) {
	data, err := os.ReadFile("../../deploy/examples/grants.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, opts); err != nil {
		t.Fatalf("deploy/examples/grants.yaml: %v", err)
	}
}

func TestStarActionSemantics(t *testing.T) {
	if got := intersect([]string{"pull", "push", "delete"}, []string{"*"}); len(got) != 3 {
		t.Fatalf("* must allow every action: %v", got)
	}
	if got := intersect([]string{"*"}, []string{"pull", "push", "delete"}); got != nil {
		t.Fatalf("requesting * needs *: %v", got)
	}
	if got := intersect([]string{"*"}, []string{"*"}); len(got) != 1 {
		t.Fatal("* with *")
	}
}

// FuzzParseScope checks that every scope accepted names a valid resource
// and only known actions.
func FuzzParseScope(f *testing.F) {
	for _, s := range []string{"repository:a/b:pull", "registry:catalog:*", "repository:a:b:c", "repository(x):a:pull"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sc, ok := ParseScope(s)
		if !ok {
			return
		}
		if sc.Type == TypeRepository && !ValidRepoName(sc.Name) {
			t.Fatalf("invalid name accepted: %q", sc.Name)
		}
		if sc.Type == TypeRegistry && sc.Name != "catalog" {
			t.Fatalf("registry scope %q accepted", sc.Name)
		}
		for _, a := range sc.Actions {
			if a != "pull" && a != "push" && a != "delete" && a != "*" {
				t.Fatalf("unknown action %q", a)
			}
		}
	})
}

// FuzzTemplateIsolation checks that a member's template never matches a
// repository outside its own namespace.
func FuzzTemplateIsolation(f *testing.F) {
	f.Add("alice", "alice/x")
	f.Add("alice", "alice-evil/x")
	pat, _ := ParsePattern("{name}/**", true)
	f.Fuzz(func(t *testing.T, name, repo string) {
		if !ValidRepoName(repo) || name == "" || strings.Contains(name, "/") {
			return
		}
		if pat.Match(repo, name) && !strings.HasPrefix(repo, name+"/") {
			t.Fatalf("%q matched %q", repo, name)
		}
	})
}
