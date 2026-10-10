// Package login verifies the signed Nostr event a client sends as its Basic
// password (PLAN.md §1).
package login

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
)

// Reason classifies why a login was refused; it labels metrics and logs.
type Reason string

const (
	ReasonBadUsername   Reason = "bad_username"
	ReasonMalformed     Reason = "malformed"
	ReasonTooLarge      Reason = "too_large"
	ReasonWrongKind     Reason = "wrong_kind"
	ReasonPubkey        Reason = "pubkey_mismatch"
	ReasonBadTags       Reason = "bad_tags"
	ReasonWrongRealm    Reason = "wrong_realm"
	ReasonWrongMethod   Reason = "wrong_method"
	ReasonWrongService  Reason = "wrong_service"
	ReasonFuture        Reason = "created_in_future"
	ReasonExpired       Reason = "expired"
	ReasonTooLong       Reason = "lifetime_too_long"
	ReasonBadSignature  Reason = "bad_signature"
	ReasonContentNotEmp Reason = "content_not_empty"
)

// Error is a refused login.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "login refused: " + string(e.Reason)
	}
	return "login refused: " + string(e.Reason) + ": " + e.Detail
}

func refuse(r Reason, format string, args ...any) error {
	return &Error{Reason: r, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf returns err's Reason, or ReasonMalformed for any other error.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonMalformed
}

// MaxPasswordSize bounds the encoded password; a login event is a few
// hundred bytes.
const MaxPasswordSize = 8192

// Options configures a Verifier.
type Options struct {
	Realm             string
	Kind              int
	MaxLifetime       time.Duration
	MinRemaining      time.Duration
	ClockSkew         time.Duration
	RequireServiceTag bool
	UsernameFormats   []string // npub, nprofile, hex
	CacheSize         int
	Now               func() time.Time
}

// Identity is a verified login.
type Identity struct {
	Pubkey  string    // lowercase hex
	Expires time.Time // the login event's expiration
	EventID string
	service string // the event's service tag, if any
}

// Verifier checks login events.
type Verifier struct {
	opts  Options
	realm string
	cache *lru
}

// New returns a Verifier; it fails if the realm is not a valid URL.
func New(opts Options) (*Verifier, error) {
	realm, err := NormalizeURL(opts.Realm)
	if err != nil {
		return nil, fmt.Errorf("login: realm: %w", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if len(opts.UsernameFormats) == 0 {
		opts.UsernameFormats = []string{"npub", "nprofile", "hex"}
	}
	return &Verifier{opts: opts, realm: realm, cache: newLRU(opts.CacheSize)}, nil
}

// ParseUsername decodes a username as a public key in one of formats.
func ParseUsername(username string, formats []string) (string, error) {
	u := strings.TrimSpace(username)
	lower := strings.ToLower(u)
	var format string
	switch {
	case strings.HasPrefix(lower, "npub1"):
		format = "npub"
	case strings.HasPrefix(lower, "nprofile1"):
		format = "nprofile"
	case strings.HasPrefix(lower, "nsec1"):
		return "", refuse(ReasonBadUsername, "a private key (nsec) was sent as the username")
	default:
		format = "hex"
	}
	if !slices.Contains(formats, format) {
		return "", refuse(ReasonBadUsername, "%s usernames are not accepted", format)
	}
	pub, err := nip19.ParsePublicKey(u)
	if err != nil {
		return "", refuse(ReasonBadUsername, "%v", err)
	}
	return pub, nil
}

// Verify checks username and password for a token request for service.
// Every time- and request-dependent check runs on each call; only the
// signature check is cached.
func (v *Verifier) Verify(username, password, service string) (Identity, error) {
	pub, err := ParseUsername(username, v.opts.UsernameFormats)
	if err != nil {
		return Identity{}, err
	}
	if len(password) > MaxPasswordSize {
		return Identity{}, refuse(ReasonTooLarge, "password is %d bytes", len(password))
	}
	key := sha256.Sum256([]byte(password))
	if id, ok := v.cache.get(key); ok {
		return v.checkCached(id, pub, service)
	}

	ev, err := decodeEvent(password)
	if err != nil {
		return Identity{}, err
	}
	id, err := v.checkEvent(ev, pub, service)
	if err != nil {
		return Identity{}, err
	}
	if err := ev.Verify(); err != nil {
		return Identity{}, refuse(ReasonBadSignature, "%v", err)
	}
	v.cache.put(key, id)
	return id, nil
}

// checkCached repeats the checks that depend on the request or the clock.
func (v *Verifier) checkCached(id Identity, pub, service string) (Identity, error) {
	if id.Pubkey != pub {
		return Identity{}, refuse(ReasonPubkey, "event pubkey differs from the username")
	}
	if err := v.checkService(id.service, service); err != nil {
		return Identity{}, err
	}
	if !id.Expires.After(v.opts.Now().Add(v.opts.MinRemaining)) {
		return Identity{}, refuse(ReasonExpired, "event expires at %s", id.Expires.UTC().Format(time.RFC3339))
	}
	return id, nil
}

func decodeEvent(password string) (*nip01.Event, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(password, "="))
	if err != nil {
		return nil, refuse(ReasonMalformed, "password is not base64url")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var ev nip01.Event
	if err := dec.Decode(&ev); err != nil {
		return nil, refuse(ReasonMalformed, "password is not a Nostr event")
	}
	if dec.More() {
		return nil, refuse(ReasonMalformed, "trailing data after the event")
	}
	return &ev, nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// checkEvent runs every check except the signature, cheapest first.
func (v *Verifier) checkEvent(ev *nip01.Event, pub, service string) (Identity, error) {
	if !isLowerHex(ev.ID, 64) || !isLowerHex(ev.PubKey, 64) || !isLowerHex(ev.Sig, 128) {
		return Identity{}, refuse(ReasonMalformed, "id, pubkey and sig must be lowercase hex")
	}
	if ev.Kind != v.opts.Kind {
		return Identity{}, refuse(ReasonWrongKind, "kind %d", ev.Kind)
	}
	if ev.PubKey != pub {
		return Identity{}, refuse(ReasonPubkey, "event pubkey differs from the username")
	}
	if ev.Content != "" {
		return Identity{}, refuse(ReasonContentNotEmp, "content must be empty")
	}

	tags := map[string]string{}
	for _, t := range ev.Tags {
		if len(t) == 0 {
			return Identity{}, refuse(ReasonBadTags, "empty tag")
		}
		switch t[0] {
		case "u", "method", "expiration", "service":
			if len(t) != 2 {
				return Identity{}, refuse(ReasonBadTags, "tag %q must have exactly one value", t[0])
			}
			if _, dup := tags[t[0]]; dup {
				return Identity{}, refuse(ReasonBadTags, "tag %q appears twice", t[0])
			}
			tags[t[0]] = t[1]
		}
	}
	for _, name := range []string{"u", "method", "expiration"} {
		if _, ok := tags[name]; !ok {
			return Identity{}, refuse(ReasonBadTags, "missing %q tag", name)
		}
	}

	u, err := NormalizeURL(tags["u"])
	if err != nil || u != v.realm {
		return Identity{}, refuse(ReasonWrongRealm, "u tag does not name this realm")
	}
	if tags["method"] != "GET" {
		return Identity{}, refuse(ReasonWrongMethod, "method must be GET")
	}
	svcTag, hasSvc := tags["service"]
	if v.opts.RequireServiceTag && !hasSvc {
		return Identity{}, refuse(ReasonWrongService, "a service tag is required")
	}
	if err := v.checkService(svcTag, service); err != nil {
		return Identity{}, err
	}

	exp, err := parseUnix(tags["expiration"])
	if err != nil {
		return Identity{}, refuse(ReasonBadTags, "expiration: %v", err)
	}
	now := v.opts.Now()
	created := time.Unix(int64(ev.CreatedAt), 0)
	if ev.CreatedAt > uint64(maxUnix) || created.After(now.Add(v.opts.ClockSkew)) {
		return Identity{}, refuse(ReasonFuture, "created_at is in the future")
	}
	if !exp.After(created) {
		return Identity{}, refuse(ReasonBadTags, "expiration is not after created_at")
	}
	if exp.Sub(created) > v.opts.MaxLifetime {
		return Identity{}, refuse(ReasonTooLong, "lifetime %s exceeds %s", exp.Sub(created), v.opts.MaxLifetime)
	}
	if !exp.After(now.Add(v.opts.MinRemaining)) {
		return Identity{}, refuse(ReasonExpired, "event expires at %s", exp.UTC().Format(time.RFC3339))
	}
	return Identity{Pubkey: pub, Expires: exp, EventID: ev.ID, service: svcTag}, nil
}

func (v *Verifier) checkService(tag, service string) error {
	if tag != "" && tag != service {
		return refuse(ReasonWrongService, "event is for service %q", tag)
	}
	return nil
}

// maxUnix bounds timestamps to year 5138, far past any real login and well
// inside time.Time's range.
const maxUnix = 1 << 37

func parseUnix(s string) (time.Time, error) {
	if s == "" || len(s) > 12 || strings.TrimLeft(s, "0123456789") != "" {
		return time.Time{}, fmt.Errorf("%q is not a unix timestamp", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxUnix {
		return time.Time{}, fmt.Errorf("%q is out of range", s)
	}
	return time.Unix(n, 0), nil
}

// NormalizeURL returns the canonical form realm URLs are compared in:
// lowercase scheme and host, no default port, no trailing slash. It
// refuses user info, queries and fragments.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("scheme must be http or https")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" {
		return "", errors.New("must be a plain absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	return scheme + "://" + host + path, nil
}
