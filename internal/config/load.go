package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// EnvPrefix starts every environment override.
const EnvPrefix = "REGISTRY_PASS_"

// Origin says where a setting's value came from.
type Origin string

const (
	FromDefault Origin = "default"
	FromFile    Origin = "file"
	FromEnv     Origin = "env"
)

// Origins maps a dotted key path ("login.maxLifetime") to where its value
// came from. Paths missing from the map are defaults.
type Origins map[string]Origin

// Of returns where path's value came from.
func (o Origins) Of(path string) Origin {
	if v, ok := o[path]; ok {
		return v
	}
	return FromDefault
}

// Load reads the config file at path (skipped when path is empty), applies
// environment overrides from environ ("KEY=value" pairs), fills source
// defaults and validates the result.
func Load(path string, environ []string) (*Config, Origins, error) {
	cfg := Default()
	origins := Origins{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("config: %w", err)
		}
		if err := decodeFile(data, &cfg, origins); err != nil {
			return nil, nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	if err := applyEnv(&cfg, environ, origins); err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	cfg.applySourceDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	return &cfg, origins, nil
}

func decodeFile(data []byte, cfg *Config, origins Origins) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("only one YAML document is allowed")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if len(root.Content) > 0 {
		markOrigins(root.Content[0], "", origins)
	}
	return nil
}

// markOrigins records every key path present in the file.
func markOrigins(n *yaml.Node, prefix string, origins Origins) {
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		path := n.Content[i].Value
		if prefix != "" {
			path = prefix + "." + path
		}
		origins[path] = FromFile
		markOrigins(n.Content[i+1], path, origins)
	}
}

// envField is one setting an environment variable can override.
type envField struct {
	path  string
	value reflect.Value
}

// envFields lists every overridable setting of cfg by environment name.
// Lists of structs (sources) and maps are file-only.
func envFields(cfg *Config) map[string]envField {
	out := map[string]envField{}
	var walk func(v reflect.Value, path, env string)
	walk = func(v reflect.Value, path, env string) {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			p, e := tag, upperSnake(tag)
			if path != "" {
				p, e = path+"."+tag, env+"__"+e
			}
			fv := v.Field(i)
			if _, ok := fv.Addr().Interface().(Setter); ok {
				out[EnvPrefix+e] = envField{p, fv}
				continue
			}
			switch fv.Kind() {
			case reflect.Struct:
				walk(fv, p, e)
			case reflect.String, reflect.Bool, reflect.Int:
				out[EnvPrefix+e] = envField{p, fv}
			case reflect.Slice:
				if fv.Type().Elem().Kind() == reflect.String {
					out[EnvPrefix+e] = envField{p, fv}
				}
			}
		}
	}
	walk(reflect.ValueOf(cfg).Elem(), "", "")
	return out
}

func applyEnv(cfg *Config, environ []string, origins Origins) error {
	fields := envFields(cfg)
	var unknown []string
	for _, kv := range environ {
		name, val, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, EnvPrefix) {
			continue
		}
		f, ok := fields[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if err := setValue(f.value, val); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		origins[f.path] = FromEnv
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown environment override(s): %s", strings.Join(unknown, ", "))
	}
	return nil
}

func setValue(v reflect.Value, s string) error {
	if setter, ok := v.Addr().Interface().(Setter); ok {
		return setter.Set(s)
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return fmt.Errorf("invalid boolean %q", s)
		}
		v.SetBool(b)
	case reflect.Int:
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid integer %q", s)
		}
		v.SetInt(int64(n))
	case reflect.Slice:
		var items []string
		for _, it := range strings.Split(s, ",") {
			if it = strings.TrimSpace(it); it != "" {
				items = append(items, it)
			}
		}
		v.Set(reflect.ValueOf(items))
	default:
		return fmt.Errorf("not settable from the environment")
	}
	return nil
}

// upperSnake turns a camelCase key into UPPER_SNAKE ("perIP" → "PER_IP",
// "staticUserCacheTTL" → "STATIC_USER_CACHE_TTL").
func upperSnake(s string) string {
	r := []rune(s)
	var b strings.Builder
	for i, c := range r {
		if i > 0 && unicode.IsUpper(c) {
			prev := r[i-1]
			nextLower := i+1 < len(r) && unicode.IsLower(r[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToUpper(c))
	}
	return b.String()
}

// EnvNames lists every environment override name, sorted.
func EnvNames() []string {
	cfg := Default()
	var names []string
	for n := range envFields(&cfg) {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
