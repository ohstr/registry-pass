// Package bytesize parses and formats storage sizes ("10GiB", "500MB").
package bytesize

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

var units = map[string]float64{
	"": 1, "b": 1,
	"k": 1e3, "kb": 1e3, "m": 1e6, "mb": 1e6, "g": 1e9, "gb": 1e9, "t": 1e12, "tb": 1e12,
	"ki": 1 << 10, "kib": 1 << 10, "mi": 1 << 20, "mib": 1 << 20,
	"gi": 1 << 30, "gib": 1 << 30, "ti": 1 << 40, "tib": 1 << 40,
}

// Parse reads a size: a number of bytes, or a number with a decimal (KB,
// MB, GB, TB) or binary (KiB, MiB, GiB, TiB) unit.
func Parse(s string) (int64, error) {
	t := strings.TrimSpace(s)
	i := strings.IndexFunc(t, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i < 0 {
		i = len(t)
	}
	num, unit := t[:i], strings.ToLower(strings.TrimSpace(t[i:]))
	mult, ok := units[unit]
	if num == "" || !ok {
		return 0, fmt.Errorf("invalid size %q, want a number of bytes or a size like 10GiB", s)
	}
	v, err := strconv.ParseFloat(num, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	n := v * mult
	if n >= math.MaxInt64 {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return int64(n), nil
}

// Format writes n in the largest binary unit that keeps it at least 1,
// with at most one decimal ("10GiB", "10.2GiB", "300B").
func Format(n int64) string {
	const unit = 1 << 10
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	v, i := float64(n), -1
	for v >= unit && i < 3 {
		v /= unit
		i++
	}
	s := strconv.FormatFloat(math.Floor(v*10)/10, 'f', -1, 64)
	return s + []string{"KiB", "MiB", "GiB", "TiB"}[i]
}
