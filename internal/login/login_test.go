package login

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/registry-pass/internal/testkit"
)

const realm = "https://pass.example/token"

var (
	alice = testkit.NewKey("alice")
	bob   = testkit.NewKey("bob")
	now   = time.Unix(1_800_000_000, 0)
)

func verifier(t *testing.T, mod func(*Options)) *Verifier {
	t.Helper()
	o := Options{
		Realm: realm, Kind: 27235, MaxLifetime: time.Hour, MinRemaining: 2 * time.Minute,
		ClockSkew: 30 * time.Second, CacheSize: 100, Now: func() time.Time { return now },
	}
	if mod != nil {
		mod(&o)
	}
	v, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	v.cache.setNow(o.Now)
	return v
}

func (c *lru) setNow(f func() time.Time) {
	if c != nil {
		c.now = f
	}
}

// resign recomputes the id and signs ev with k (after a test edits it).
func resign(ev *nip01.Event, k testkit.Key) *nip01.Event {
	if err := ev.Sign(k.Priv); err != nil {
		panic(err)
	}
	return ev
}

func valid(extra ...[]string) *nip01.Event {
	return alice.LoginEvent(realm, now, 30*time.Minute, extra...)
}

func withTag(ev *nip01.Event, name, value string) *nip01.Event {
	for i, t := range ev.Tags {
		if t[0] == name {
			ev.Tags[i] = []string{name, value}
		}
	}
	return ev
}

func TestVerify(t *testing.T) {
	exp := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	cases := []struct {
		name     string
		user     string
		password func() string
		service  string
		mod      func(*Options)
		want     Reason // "" = accepted
	}{
		{name: "valid npub", user: alice.Npub, password: func() string { return testkit.Password(valid()) }},
		{name: "valid hex", user: alice.Pub, password: func() string { return testkit.Password(valid()) }},
		{name: "valid uppercase hex username", user: strings.ToUpper(alice.Pub), password: func() string { return testkit.Password(valid()) }},
		{name: "valid padded base64", user: alice.Npub, password: func() string {
			data, _ := json.Marshal(valid())
			return base64.URLEncoding.EncodeToString(data)
		}},
		{name: "valid nprofile", user: mustNprofile(alice.Pub), password: func() string { return testkit.Password(valid()) }},
		{name: "valid service tag", user: alice.Npub, service: "registry.example",
			password: func() string { return testkit.Password(valid([]string{"service", "registry.example"})) }},
		{name: "realm with trailing slash, default port, uppercase host", user: alice.Npub,
			password: func() string {
				return testkit.Password(resign(withTag(valid(), "u", "https://PASS.example:443/token/"), alice))
			}},
		{name: "created within clock skew", user: alice.Npub,
			password: func() string {
				return testkit.Password(alice.LoginEvent(realm, now.Add(20*time.Second), 30*time.Minute))
			}},

		// identity and key confusion
		{name: "nsec as username", user: alice.Nsec, password: func() string { return testkit.Password(valid()) }, want: ReasonBadUsername},
		{name: "garbage username", user: "alice", password: func() string { return testkit.Password(valid()) }, want: ReasonBadUsername},
		{name: "off-curve hex username", user: strings.Repeat("f", 64), password: func() string { return testkit.Password(valid()) }, want: ReasonBadUsername},
		{name: "hex disabled", user: alice.Pub, mod: func(o *Options) { o.UsernameFormats = []string{"npub"} },
			password: func() string { return testkit.Password(valid()) }, want: ReasonBadUsername},
		{name: "someone else's event under my name", user: bob.Npub, password: func() string { return testkit.Password(valid()) }, want: ReasonPubkey},
		{name: "attacker signs event claiming victim pubkey", user: alice.Npub, password: func() string {
			ev := bob.LoginEvent(realm, now, 30*time.Minute)
			ev.PubKey = alice.Pub
			id, _ := ev.HashID()
			ev.ID = hexs(id)
			return testkit.Password(ev)
		}, want: ReasonBadSignature},

		// tampering
		{name: "flipped signature", user: alice.Npub, password: func() string {
			ev := valid()
			ev.Sig = flip(ev.Sig)
			return testkit.Password(ev)
		}, want: ReasonBadSignature},
		{name: "extended expiration without re-signing", user: alice.Npub, password: func() string {
			return testkit.Password(withTag(valid(), "expiration", exp(50*time.Minute)))
		}, want: ReasonBadSignature},
		{name: "extended expiration with recomputed id, old sig", user: alice.Npub, password: func() string {
			ev := withTag(valid(), "expiration", exp(50*time.Minute))
			id, _ := ev.HashID()
			ev.ID = hexs(id)
			return testkit.Password(ev)
		}, want: ReasonBadSignature},
		{name: "uppercase hex id", user: alice.Npub, password: func() string {
			ev := valid()
			ev.ID = strings.ToUpper(ev.ID)
			return testkit.Password(ev)
		}, want: ReasonMalformed},

		// wrong purpose
		{name: "kind 1 note with login tags", user: alice.Npub, password: func() string {
			ev := valid()
			ev.Kind = 1
			return testkit.Password(resign(ev, alice))
		}, want: ReasonWrongKind},
		{name: "NIP-98 event for another site", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent("https://other.example/api", now, 30*time.Minute))
		}, want: ReasonWrongRealm},
		{name: "realm host suffix", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent("https://pass.example.evil.com/token", now, 30*time.Minute))
		}, want: ReasonWrongRealm},
		{name: "realm http downgrade", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent("http://pass.example/token", now, 30*time.Minute))
		}, want: ReasonWrongRealm},
		{name: "realm with user info", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent("https://evil@pass.example/token", now, 30*time.Minute))
		}, want: ReasonWrongRealm},
		{name: "realm with query", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent(realm+"?scope=x", now, 30*time.Minute))
		}, want: ReasonWrongRealm},
		{name: "realm dot segments", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent("https://pass.example/x/../token", now, 30*time.Minute))
		}, want: ReasonWrongRealm},
		{name: "realm other path", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent("https://pass.example/token2", now, 30*time.Minute))
		}, want: ReasonWrongRealm},
		{name: "method POST", user: alice.Npub, password: func() string {
			return testkit.Password(resign(withTag(valid(), "method", "POST"), alice))
		}, want: ReasonWrongMethod},
		{name: "duplicate u tag smuggling a second realm", user: alice.Npub, password: func() string {
			return testkit.Password(valid([]string{"u", "https://other.example/"}))
		}, want: ReasonBadTags},
		{name: "duplicate expiration", user: alice.Npub, password: func() string {
			return testkit.Password(valid([]string{"expiration", exp(5 * time.Minute)}))
		}, want: ReasonBadTags},
		{name: "tag with extra values", user: alice.Npub, password: func() string {
			ev := valid()
			ev.Tags[0] = []string{"u", realm, "extra"}
			return testkit.Password(resign(ev, alice))
		}, want: ReasonBadTags},
		{name: "empty tag", user: alice.Npub, password: func() string {
			return testkit.Password(valid([]string{}))
		}, want: ReasonBadTags},
		{name: "missing expiration", user: alice.Npub, password: func() string {
			return testkit.Password(alice.Sign(27235, now, "", []string{"u", realm}, []string{"method", "GET"}))
		}, want: ReasonBadTags},
		{name: "content not empty", user: alice.Npub, password: func() string {
			ev := valid()
			ev.Content = "hi"
			return testkit.Password(resign(ev, alice))
		}, want: ReasonContentNotEmp},

		// service
		{name: "service tag for another registry", user: alice.Npub, service: "registry.example",
			password: func() string { return testkit.Password(valid([]string{"service", "other.example"})) }, want: ReasonWrongService},
		{name: "service tag required", user: alice.Npub, service: "registry.example", mod: func(o *Options) { o.RequireServiceTag = true },
			password: func() string { return testkit.Password(valid()) }, want: ReasonWrongService},

		// time
		{name: "expired", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent(realm, now.Add(-40*time.Minute), 30*time.Minute))
		}, want: ReasonExpired},
		{name: "expires within minRemaining", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent(realm, now.Add(-29*time.Minute), 30*time.Minute))
		}, want: ReasonExpired},
		{name: "created in the future", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent(realm, now.Add(5*time.Minute), 30*time.Minute))
		}, want: ReasonFuture},
		{name: "lifetime too long", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent(realm, now, 2*time.Hour))
		}, want: ReasonTooLong},
		{name: "backdated to stretch lifetime", user: alice.Npub, password: func() string {
			return testkit.Password(alice.LoginEvent(realm, now.Add(-24*time.Hour), 25*time.Hour))
		}, want: ReasonTooLong},
		{name: "expiration before created_at", user: alice.Npub, password: func() string {
			return testkit.Password(resign(withTag(valid(), "expiration", exp(-time.Minute)), alice))
		}, want: ReasonBadTags},
		{name: "negative expiration", user: alice.Npub, password: func() string {
			return testkit.Password(resign(withTag(valid(), "expiration", "-1"), alice))
		}, want: ReasonBadTags},
		{name: "signed expiration", user: alice.Npub, password: func() string {
			return testkit.Password(resign(withTag(valid(), "expiration", "+"+exp(time.Minute)), alice))
		}, want: ReasonBadTags},
		{name: "huge expiration", user: alice.Npub, password: func() string {
			return testkit.Password(resign(withTag(valid(), "expiration", "99999999999999999999"), alice))
		}, want: ReasonBadTags},
		{name: "huge created_at", user: alice.Npub, password: func() string {
			ev := valid()
			ev.CreatedAt = 1 << 63
			return testkit.Password(resign(ev, alice))
		}, want: ReasonFuture},

		// encoding
		{name: "not base64", user: alice.Npub, password: func() string { return "!!!" }, want: ReasonMalformed},
		{name: "std base64 alphabet", user: alice.Npub, password: func() string {
			data, _ := json.Marshal(valid())
			s := base64.StdEncoding.EncodeToString(data)
			if !strings.ContainsAny(s, "+/") {
				return "+" + s
			}
			return s
		}, want: ReasonMalformed},
		{name: "not json", user: alice.Npub, password: func() string { return base64.RawURLEncoding.EncodeToString([]byte("hello")) }, want: ReasonMalformed},
		{name: "unknown json field", user: alice.Npub, password: func() string {
			data, _ := json.Marshal(valid())
			data = append(data[:len(data)-1], []byte(`,"extra":1}`)...)
			return base64.RawURLEncoding.EncodeToString(data)
		}, want: ReasonMalformed},
		{name: "two events concatenated", user: alice.Npub, password: func() string {
			data, _ := json.Marshal(valid())
			return base64.RawURLEncoding.EncodeToString(append(data, data...))
		}, want: ReasonMalformed},
		{name: "oversized password", user: alice.Npub, password: func() string { return strings.Repeat("A", MaxPasswordSize+1) }, want: ReasonTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := verifier(t, tc.mod)
			id, err := v.Verify(tc.user, tc.password(), tc.service)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if id.Pubkey != alice.Pub {
					t.Fatalf("identity %s, want alice", id.Pubkey)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want %s", tc.want)
			}
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("reason %s, want %s (%v)", got, tc.want, err)
			}
		})
	}
}

func TestCacheRechecksPerRequest(t *testing.T) {
	clock := now
	v := verifier(t, func(o *Options) { o.Now = func() time.Time { return clock } })
	pw := testkit.Password(alice.LoginEvent(realm, now, 30*time.Minute, []string{"service", "registry.example"}))

	if _, err := v.Verify(alice.Npub, pw, "registry.example"); err != nil {
		t.Fatal(err)
	}
	if v.cache.len() != 1 {
		t.Fatal("verified login not cached")
	}
	// A cached password presented under another name is still refused.
	if _, err := v.Verify(bob.Npub, pw, "registry.example"); ReasonOf(err) != ReasonPubkey {
		t.Fatalf("cache let bob reuse alice's event: %v", err)
	}
	// ... or for another service.
	if _, err := v.Verify(alice.Npub, pw, "other.example"); ReasonOf(err) != ReasonWrongService {
		t.Fatalf("cache ignored the service: %v", err)
	}
	// ... or after it expires.
	clock = now.Add(29 * time.Minute)
	if _, err := v.Verify(alice.Npub, pw, "registry.example"); ReasonOf(err) != ReasonExpired {
		t.Fatalf("cache served an expiring event: %v", err)
	}
}

func TestCacheNeverStoresFailures(t *testing.T) {
	v := verifier(t, nil)
	ev := valid()
	ev.Sig = flip(ev.Sig)
	for range 3 {
		if _, err := v.Verify(alice.Npub, testkit.Password(ev), ""); ReasonOf(err) != ReasonBadSignature {
			t.Fatal(err)
		}
	}
	if v.cache.len() != 0 {
		t.Fatal("failed login cached")
	}
}

func TestCacheDisabledAndBounded(t *testing.T) {
	v := verifier(t, func(o *Options) { o.CacheSize = 0 })
	if _, err := v.Verify(alice.Npub, testkit.Password(valid()), ""); err != nil {
		t.Fatal(err)
	}
	if v.cache.len() != 0 {
		t.Fatal("cache size 0 still caches")
	}
	v = verifier(t, func(o *Options) { o.CacheSize = 2 })
	for i := range 5 {
		ev := alice.LoginEvent(realm, now.Add(-time.Duration(i)*time.Second), 30*time.Minute)
		if _, err := v.Verify(alice.Npub, testkit.Password(ev), ""); err != nil {
			t.Fatal(err)
		}
	}
	if v.cache.len() != 2 {
		t.Fatalf("cache grew to %d", v.cache.len())
	}
}

func TestConcurrentVerify(t *testing.T) {
	v := verifier(t, nil)
	pw := testkit.Password(valid())
	bad := valid()
	bad.Sig = flip(bad.Sig)
	badPw := testkit.Password(bad)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				if _, err := v.Verify(alice.Npub, pw, ""); err != nil {
					t.Error(err)
				}
			} else if _, err := v.Verify(alice.Npub, badPw, ""); err == nil {
				t.Error("forged event accepted under concurrency")
			}
		}()
	}
	wg.Wait()
}

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://Pass.Example:443/token/": "https://pass.example/token",
		"http://pass.example:80":          "http://pass.example",
		"https://pass.example:8443/t":     "https://pass.example:8443/t",
		"https://[::1]:5001/token":        "https://[::1]:5001/token",
	} {
		if got, err := NormalizeURL(in); err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp://x/", "https://x/?a", "https://x/#f", "https://u@x/", "/token", "https:opaque", "https://x/?"} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) accepted", bad)
		}
	}
	if _, err := New(Options{Realm: "not a url"}); err == nil {
		t.Error("New accepted a bad realm")
	}
}

func TestErrorText(t *testing.T) {
	if (&Error{Reason: ReasonExpired}).Error() != "login refused: expired" {
		t.Fatal("Error text")
	}
	if ReasonOf(nil) != ReasonMalformed {
		t.Fatal("ReasonOf(other)")
	}
}

// FuzzVerify checks that no input panics and that anything accepted really
// is a valid signed login event for this realm.
func FuzzVerify(f *testing.F) {
	f.Add(alice.Npub, testkit.Password(valid()))
	f.Add(alice.Pub, "e30")
	f.Add("npub1", "")
	f.Fuzz(func(t *testing.T, user, password string) {
		v := verifier(t, nil)
		id, err := v.Verify(user, password, "")
		if err != nil {
			return
		}
		ev, derr := decodeEvent(password)
		if derr != nil || ev.Verify() != nil || ev.PubKey != id.Pubkey {
			t.Fatalf("accepted an invalid login for %q", user)
		}
	})
}

func flip(hexSig string) string {
	b := []byte(hexSig)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

func hexs(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

func mustNprofile(pub string) string {
	s, err := nip19.EncodeProfile(pub, nil)
	if err != nil {
		panic(err)
	}
	return s
}
