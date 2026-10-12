package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/registry-pass/internal/bytesize"
	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration written as a Go duration string ("5m", "1h").
type Duration time.Duration

// D returns d as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// Set parses s as a duration.
func (d *Duration) Set(s string) error {
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", s)
	}
	*d = Duration(v)
	return nil
}

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string like 5m", n.Line)
	}
	if err := d.Set(n.Value); err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Rate is a number of events per period, written "300/min".
type Rate struct {
	N   int
	Per time.Duration
}

// Zero reports whether r is unset (no limit).
func (r Rate) Zero() bool { return r.N == 0 }

// PerSecond returns r as events per second.
func (r Rate) PerSecond() float64 {
	if r.Per <= 0 {
		return 0
	}
	return float64(r.N) / r.Per.Seconds()
}

func (r Rate) String() string {
	if r.Zero() {
		return "0"
	}
	unit := map[time.Duration]string{time.Second: "s", time.Minute: "min", time.Hour: "h"}[r.Per]
	return fmt.Sprintf("%d/%s", r.N, unit)
}

// Set parses s as "N/unit" with unit s, sec, second, min, minute, h, hour;
// "0" means no limit.
func (r *Rate) Set(s string) error {
	s = strings.TrimSpace(s)
	if s == "0" {
		*r = Rate{}
		return nil
	}
	num, unit, ok := strings.Cut(s, "/")
	if !ok {
		return fmt.Errorf("invalid rate %q, want N/unit like 300/min", s)
	}
	n, err := strconv.Atoi(strings.TrimSpace(num))
	if err != nil || n < 0 {
		return fmt.Errorf("invalid rate %q", s)
	}
	var per time.Duration
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "s", "sec", "second":
		per = time.Second
	case "min", "minute":
		per = time.Minute
	case "h", "hour":
		per = time.Hour
	default:
		return fmt.Errorf("invalid rate unit in %q, want s, min or h", s)
	}
	*r = Rate{N: n, Per: per}
	return nil
}

func (r *Rate) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: rate must be a string like 300/min", n.Line)
	}
	if err := r.Set(n.Value); err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	return nil
}

func (r Rate) MarshalYAML() (any, error) { return r.String(), nil }

// Size is a number of bytes written as a size like "10GiB".
type Size int64

// Bytes returns s as a number of bytes.
func (s Size) Bytes() int64 { return int64(s) }

func (s Size) String() string { return bytesize.Format(int64(s)) }

// Set parses v as a size.
func (s *Size) Set(v string) error {
	n, err := bytesize.Parse(v)
	if err != nil {
		return err
	}
	*s = Size(n)
	return nil
}

func (s *Size) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: size must be a string like 10GiB", n.Line)
	}
	if err := s.Set(n.Value); err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	return nil
}

func (s Size) MarshalYAML() (any, error) { return s.String(), nil }

// Setter is implemented by scalar types that env overrides can set.
type Setter interface{ Set(string) error }
