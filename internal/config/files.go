package config

import (
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxSecretSize bounds a secret file so a misconfigured path can't make the
// process read something huge.
const maxSecretSize = 1 << 20

func readSecret(path string) (string, error) {
	data, err := ReadFileLimited(path, maxSecretSize)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadSecret reads a secret file's trimmed contents.
func ReadSecret(path string) (string, error) {
	s, err := readSecret(path)
	if err == nil && s == "" {
		err = fmt.Errorf("%s: empty", path)
	}
	return s, err
}

// ReadFileLimited reads path, refusing files larger than limit bytes.
func ReadFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return data, nil
}

// CheckFiles reports every file the configuration names that can't be read.
func (cfg *Config) CheckFiles() error {
	c := &checker{}
	check := func(name, path string) {
		if path == "" {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			c.addf("%s: %v", name, err)
			return
		}
		f.Close()
	}
	check("token.signingKeyFile", cfg.Token.SigningKeyFile)
	check("token.certificateFile", cfg.Token.CertificateFile)
	check("token.chainFile", cfg.Token.ChainFile)
	check("server.tls.certFile", cfg.Server.TLS.CertFile)
	check("server.tls.keyFile", cfg.Server.TLS.KeyFile)
	check("grants.file", cfg.Grants.File)
	if cfg.Quota.Enabled {
		check("quota.registryCAFile", cfg.Quota.RegistryCAFile)
		if _, err := ReadSecret(cfg.Quota.EventsTokenFile); err != nil {
			c.addf("quota.eventsTokenFile: %v", err)
		}
	}
	if cfg.Membership.Enabled {
		for i, s := range cfg.Membership.Sources {
			where := fmt.Sprintf("membership.sources[%d]", i)
			switch {
			case s.Relay != nil && s.Relay.Reader != nil:
				check(where+".relay.reader.keyFile", s.Relay.Reader.KeyFile)
			case s.File != nil:
				check(where+".file.path", s.File.Path)
			case s.HTTP != nil:
				check(where+".http.caFile", s.HTTP.CAFile)
				for k, v := range s.HTTP.Headers {
					if _, _, err := ResolveFileRef(v, true); err != nil {
						c.addf("%s.http.headers[%s]: %v", where, k, err)
					}
				}
			}
		}
	}
	if len(c.problems) > 0 {
		return &ValidationError{Problems: c.problems}
	}
	return nil
}

// Print writes the effective configuration as YAML, each value annotated
// with where it came from. Header values are redacted.
func Print(w io.Writer, cfg *Config, origins Origins) error {
	redacted := *cfg
	redacted.Membership.Sources = make([]Source, len(cfg.Membership.Sources))
	for i, s := range cfg.Membership.Sources {
		if s.HTTP != nil {
			h := *s.HTTP
			h.Headers = map[string]string{}
			for k, v := range s.HTTP.Headers {
				if _, isRef, _ := ResolveFileRef(v, false); isRef {
					h.Headers[k] = v
				} else {
					h.Headers[k] = "<redacted>"
				}
			}
			s.HTTP = &h
		}
		redacted.Membership.Sources[i] = s
	}
	var root yaml.Node
	if err := root.Encode(&redacted); err != nil {
		return err
	}
	annotate(&root, "", origins)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(&root)
}

func annotate(n *yaml.Node, prefix string, origins Origins) {
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		path := k.Value
		if prefix != "" {
			path = prefix + "." + k.Value
		}
		switch v.Kind {
		case yaml.MappingNode:
			annotate(v, path, origins)
		case yaml.SequenceNode:
			// A comment on the list itself would print after its last item,
			// next to the following key; put it on this key instead.
			k.LineComment = string(origins.Of(path))
		default:
			v.LineComment = string(origins.Of(path))
		}
	}
}
