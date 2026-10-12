// Package grants decides what each identity may do: the
// grants file, repository patterns and the intersection with what a token
// request asks for.
package grants

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/ohstr/nmilat/nip19"
	"gopkg.in/yaml.v3"
)

// Grant is one entry of the grants file.
type Grant struct {
	Repos   string   `yaml:"repos"`
	Actions []string `yaml:"actions"`
	// Reserve false marks a grant into a member's own namespace (a CI or
	// agent key for alice/**), so autoReserve doesn't reserve the name and
	// lock the member out of it.
	Reserve *bool `yaml:"reserve,omitempty"`
}

// StaticUserSpec is a Basic user with a bcrypt password.
type StaticUserSpec struct {
	Bcrypt string  `yaml:"bcrypt"`
	Grants []Grant `yaml:"grants"`
}

// File is the grants file as written.
type File struct {
	Templates     []Grant                   `yaml:"templates"`
	ReservedNames []string                  `yaml:"reservedNames"`
	Anonymous     []Grant                   `yaml:"anonymous"`
	Identities    map[string][]Grant        `yaml:"identities"`
	StaticUsers   map[string]StaticUserSpec `yaml:"staticUsers"`
	Catalog       []string                  `yaml:"catalog"`
	Deny          []string                  `yaml:"deny"`
}

// Options are the grants settings from the main config.
type Options struct {
	NamePattern string
	AutoReserve bool
}

type rule struct {
	pattern Pattern
	actions []string
}

// Policy is a validated, compiled grants file. It is immutable.
type Policy struct {
	templates   []rule
	anonymous   []rule
	identities  map[string][]rule
	staticUsers map[string]staticUser
	catalog     map[string]bool
	deny        map[string]bool
	reserved    map[string]bool
	names       *regexp.Regexp
}

var staticUserName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// maxDoubleStars bounds "**" per pattern so matching stays cheap.
const maxDoubleStars = 2

// Parse validates and compiles a grants file.
func Parse(data []byte, opts Options) (*Policy, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("grants: %w", err)
	}
	names, err := regexp.Compile(opts.NamePattern)
	if err != nil {
		return nil, fmt.Errorf("grants: name pattern: %w", err)
	}
	p := &Policy{
		identities:  map[string][]rule{},
		staticUsers: map[string]staticUser{},
		catalog:     map[string]bool{},
		deny:        map[string]bool{},
		reserved:    map[string]bool{},
		names:       names,
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	compile := func(where string, gs []Grant, allowName bool) []rule {
		var out []rule
		for i, g := range gs {
			pat, err := ParsePattern(g.Repos, allowName)
			if err != nil {
				add("%s[%d]: %v", where, i, err)
				continue
			}
			if strings.Count(g.Repos, "**") > maxDoubleStars {
				add("%s[%d]: at most %d ** per pattern", where, i, maxDoubleStars)
				continue
			}
			if allowName && !pat.HasName() {
				add("%s[%d]: a template must use {name}", where, i)
				continue
			}
			if allowName && g.Reserve != nil {
				add("%s[%d]: reserve has no meaning on a template", where, i)
				continue
			}
			if len(g.Actions) == 0 {
				add("%s[%d]: no actions", where, i)
				continue
			}
			var acts []string
			for _, a := range g.Actions {
				if !slices.Contains(knownActions, a) {
					add("%s[%d]: unknown action %q", where, i, a)
					continue
				}
				if !slices.Contains(acts, a) {
					acts = append(acts, a)
				}
			}
			sort.Strings(acts)
			out = append(out, rule{pattern: pat, actions: acts})
			if opts.AutoReserve && !allowName && (g.Reserve == nil || *g.Reserve) {
				if first, ok := pat.LiteralFirst(); ok {
					p.reserved[first] = true
				}
			}
		}
		return out
	}

	p.templates = compile("templates", f.Templates, true)
	p.anonymous = compile("anonymous", f.Anonymous, false)

	for raw, gs := range f.Identities {
		pub, err := nip19.ParsePublicKey(raw)
		if err != nil {
			add("identities[%s]: %v", short(raw), err)
			continue
		}
		if _, dup := p.identities[pub]; dup {
			add("identities[%s]: the same public key is listed twice", short(raw))
			continue
		}
		p.identities[pub] = compile("identities["+short(raw)+"]", gs, false)
	}

	for name, spec := range f.StaticUsers {
		if !staticUserName.MatchString(name) {
			add("staticUsers[%s]: invalid user name", name)
			continue
		}
		if looksLikeKey(name) {
			add("staticUsers[%s]: a user name must not look like a public key", name)
			continue
		}
		su, err := newStaticUser(spec.Bcrypt)
		if err != nil {
			add("staticUsers[%s]: %v", name, err)
			continue
		}
		su.rules = compile("staticUsers["+name+"].grants", spec.Grants, false)
		p.staticUsers[name] = su
	}

	parseKeys := func(where string, keys []string, into map[string]bool) {
		for i, raw := range keys {
			pub, err := nip19.ParsePublicKey(raw)
			if err != nil {
				add("%s[%d]: %v", where, i, err)
				continue
			}
			if into[pub] {
				add("%s[%d]: the same public key is listed twice", where, i)
			}
			into[pub] = true
		}
	}
	parseKeys("catalog", f.Catalog, p.catalog)
	parseKeys("deny", f.Deny, p.deny)

	for _, n := range f.ReservedNames {
		if !names.MatchString(n) {
			add("reservedNames: %q does not match the member name pattern", n)
		}
		p.reserved[n] = true
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, &Error{Problems: problems}
	}
	return p, nil
}

// Error lists every problem in a grants file.
type Error struct{ Problems []string }

func (e *Error) Error() string {
	return "invalid grants file:\n  - " + strings.Join(e.Problems, "\n  - ")
}

func short(s string) string {
	if len(s) > 16 {
		return s[:12] + "…"
	}
	return s
}

func looksLikeKey(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "npub1") || strings.HasPrefix(lower, "nprofile1") || strings.HasPrefix(lower, "nsec1") {
		return true
	}
	_, err := nip19.ParsePublicKey(name)
	return err == nil || len(name) == 64
}

// Subject is who a token is for.
type Subject struct {
	// Anonymous is a request without credentials.
	Anonymous bool
	// StaticUser is set for a Basic static user.
	StaticUser string
	// Pubkey is the verified public key (hex) for a Nostr login.
	Pubkey string
	// MemberName is the member's name when the pubkey is an alive member
	// and membership may be used; empty otherwise.
	MemberName string
}

// Denied reports whether pubkey is on the deny list.
func (p *Policy) Denied(pubkey string) bool { return p.deny[pubkey] }

// ReadAll reports whether pubkey may list the whole catalog.
func (p *Policy) ReadAll(pubkey string) bool { return p.catalog[pubkey] && !p.deny[pubkey] }

// IsStaticUser reports whether name is a configured static user.
func (p *Policy) IsStaticUser(name string) bool {
	_, ok := p.staticUsers[name]
	return ok
}

// ValidMemberName reports whether name may receive template grants.
func (p *Policy) ValidMemberName(name string) bool {
	return name != "" && p.names.MatchString(name) && !p.reserved[name]
}

// Reserved reports whether name is reserved.
func (p *Policy) Reserved(name string) bool { return p.reserved[name] }

func (p *Policy) rulesFor(s Subject) []rule {
	switch {
	case s.Anonymous:
		return p.anonymous
	case s.StaticUser != "":
		su, ok := p.staticUsers[s.StaticUser]
		if !ok {
			return nil
		}
		return su.rules
	case s.Pubkey != "":
		if p.deny[s.Pubkey] {
			return nil
		}
		rules := slices.Clone(p.identities[s.Pubkey])
		if p.ValidMemberName(s.MemberName) {
			rules = append(rules, p.templates...)
		}
		return rules
	}
	return nil
}

// Authorize returns what s is granted of the requested scopes: for each
// scope, the intersection of requested and allowed actions; scopes with
// nothing granted are omitted.
func (p *Policy) Authorize(s Subject, scopes []Scope) []Access {
	if s.Pubkey != "" && p.deny[s.Pubkey] {
		return nil
	}
	rules := p.rulesFor(s)
	var out []Access
	for _, sc := range scopes {
		var allowed []string
		switch sc.Type {
		case TypeRegistry:
			if s.Pubkey != "" && p.catalog[s.Pubkey] {
				allowed = []string{ActionAll}
			}
		case TypeRepository:
			for _, r := range rules {
				if r.pattern.Match(sc.Name, s.MemberName) {
					for _, a := range r.actions {
						if !slices.Contains(allowed, a) {
							allowed = append(allowed, a)
						}
					}
				}
			}
		}
		if got := intersect(sc.Actions, allowed); len(got) > 0 {
			out = append(out, Access{Type: sc.Type, Name: sc.Name, Actions: got})
		}
	}
	return out
}

// HasAnonymous reports whether any grant applies without credentials.
func (p *Policy) HasAnonymous() bool { return len(p.anonymous) > 0 }
