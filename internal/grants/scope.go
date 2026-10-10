package grants

import (
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Resource types a token can grant.
const (
	TypeRepository = "repository"
	TypeRegistry   = "registry"
)

// Actions a grant can name.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
	ActionAll    = "*"
)

var knownActions = []string{ActionPull, ActionPush, ActionDelete, ActionAll}

// Scope is one requested resource and its actions.
type Scope struct {
	Type    string
	Name    string
	Actions []string
}

// Access is one granted resource, as it appears in the JWT `access` claim.
type Access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// MaxRepoNameLength matches Distribution's limit on repository names.
const MaxRepoNameLength = 255

// repoName is Distribution's repository path grammar (no host): lowercase
// components separated by single slashes.
var repoName = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)

// ValidRepoName reports whether name is a repository name Distribution
// accepts.
func ValidRepoName(name string) bool {
	return len(name) <= MaxRepoNameLength && repoName.MatchString(name)
}

// ParseScope parses "type[(class)]:name:action[,action]". Anything that
// isn't a plain repository or registry scope with a valid name is
// reported as not ok, and the caller omits it.
func ParseScope(s string) (Scope, bool) {
	first := strings.Index(s, ":")
	last := strings.LastIndex(s, ":")
	if first <= 0 || last == first {
		return Scope{}, false
	}
	typ, name, acts := s[:first], s[first+1:last], s[last+1:]
	if typ != TypeRepository && typ != TypeRegistry {
		return Scope{}, false
	}
	switch typ {
	case TypeRepository:
		if !ValidRepoName(name) {
			return Scope{}, false
		}
	case TypeRegistry:
		if name != "catalog" {
			return Scope{}, false
		}
	}
	var actions []string
	for _, a := range strings.Split(acts, ",") {
		if slices.Contains(knownActions, a) && !slices.Contains(actions, a) {
			actions = append(actions, a)
		}
	}
	if len(actions) == 0 {
		return Scope{}, false
	}
	sort.Strings(actions)
	return Scope{Type: typ, Name: name, Actions: actions}, true
}

// ParseScopes parses every scope parameter value; each value may hold
// several space-separated scopes. Duplicates of a resource are merged.
func ParseScopes(values []string) []Scope {
	byKey := map[string]*Scope{}
	var order []string
	for _, v := range values {
		for _, part := range strings.Fields(v) {
			sc, ok := ParseScope(part)
			if !ok {
				continue
			}
			key := sc.Type + ":" + sc.Name
			if prev, seen := byKey[key]; seen {
				for _, a := range sc.Actions {
					if !slices.Contains(prev.Actions, a) {
						prev.Actions = append(prev.Actions, a)
					}
				}
				sort.Strings(prev.Actions)
				continue
			}
			byKey[key] = &sc
			order = append(order, key)
		}
	}
	out := make([]Scope, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// intersect returns the requested actions that allowed permits.
func intersect(requested, allowed []string) []string {
	var out []string
	for _, a := range requested {
		if slices.Contains(allowed, a) || (a != ActionAll && slices.Contains(allowed, ActionAll)) {
			out = append(out, a)
		}
	}
	return out
}
