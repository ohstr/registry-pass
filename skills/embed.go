// Package skills embeds the agent skills shipped in this directory, so
// `registry-pass skills` can serve them from the binary alone.
package skills

import "embed"

// FS holds every skill directory (registry-pass-*/SKILL.md plus references/).
//
//go:embed registry-pass-*
var FS embed.FS
