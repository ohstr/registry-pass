package grants

import (
	"fmt"
	"regexp"
	"strings"
)

// NamePlaceholder is replaced by a member's name in template patterns.
const NamePlaceholder = "{name}"

// repoComponent is one segment of Distribution's repository path grammar.
var repoComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*$`)

var patternSegment = regexp.MustCompile(`^(\*\*|[a-z0-9._*-]+|\{name\})$`)

// Pattern matches repository names segment by segment: "*" inside a
// segment matches any run of characters within that segment, a "**"
// segment matches one or more whole segments. Matching never crosses a
// "/" except through "**", so "alice/**" can't match "alice-evil/x".
type Pattern struct {
	raw  string
	segs []string
}

// ParsePattern validates p. allowName permits the {name} placeholder.
func ParsePattern(p string, allowName bool) (Pattern, error) {
	if p == "" {
		return Pattern{}, fmt.Errorf("empty pattern")
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if !patternSegment.MatchString(s) {
			return Pattern{}, fmt.Errorf("pattern %q: invalid segment %q", p, s)
		}
		if strings.Contains(s, "**") && s != "**" {
			return Pattern{}, fmt.Errorf("pattern %q: ** must be a whole segment", p)
		}
		if s != "**" && s != NamePlaceholder && !repoComponent.MatchString(strings.ReplaceAll(s, "*", "a")) {
			return Pattern{}, fmt.Errorf("pattern %q: segment %q is not a repository path component", p, s)
		}
		if s == NamePlaceholder && !allowName {
			return Pattern{}, fmt.Errorf("pattern %q: {name} is only allowed in templates", p)
		}
	}
	return Pattern{raw: p, segs: segs}, nil
}

func (p Pattern) String() string { return p.raw }

// HasName reports whether the pattern uses {name}.
func (p Pattern) HasName() bool {
	for _, s := range p.segs {
		if s == NamePlaceholder {
			return true
		}
	}
	return false
}

// LiteralFirst returns the pattern's first segment when it is a literal
// (no wildcard, no placeholder).
func (p Pattern) LiteralFirst() (string, bool) {
	s := p.segs[0]
	if s == "**" || s == NamePlaceholder || strings.Contains(s, "*") {
		return "", false
	}
	return s, true
}

// Match reports whether repo matches, with {name} bound to name. A pattern
// with {name} never matches when name is empty.
func (p Pattern) Match(repo, name string) bool {
	if p.HasName() && name == "" {
		return false
	}
	return matchSegs(p.segs, strings.Split(repo, "/"), name)
}

func matchSegs(pat, repo []string, name string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			for i := 1; i <= len(repo); i++ {
				if matchSegs(rest, repo[i:], name) {
					return true
				}
			}
			return false
		}
		if len(repo) == 0 || !matchSegment(pat[0], repo[0], name) {
			return false
		}
		pat, repo = pat[1:], repo[1:]
	}
	return len(repo) == 0
}

func matchSegment(pat, seg, name string) bool {
	if pat == NamePlaceholder {
		return seg == name
	}
	if !strings.Contains(pat, "*") {
		return pat == seg
	}
	parts := strings.Split(pat, "*")
	if !strings.HasPrefix(seg, parts[0]) {
		return false
	}
	seg = seg[len(parts[0]):]
	for i, part := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(seg, part)
		}
		idx := strings.Index(seg, part)
		if idx < 0 {
			return false
		}
		seg = seg[idx+len(part):]
	}
	return true
}
