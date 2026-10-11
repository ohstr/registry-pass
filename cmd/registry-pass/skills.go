package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ohstr/registry-pass/skills"
	"gopkg.in/yaml.v3"
)

const skillsUsage = `usage: registry-pass skills <command>

commands:
  list                         list the built-in agent skills
  show <name> [file]           print a skill's SKILL.md, or one of its files
  install --dir D [--force] [name...]
                               copy skills into your agent's skills directory
`

type skill struct {
	Name        string
	Description string
	Files       []string
}

func loadSkills() ([]skill, error) {
	dirs, err := fs.ReadDir(skills.FS, ".")
	if err != nil {
		return nil, err
	}
	var out []skill
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		data, err := fs.ReadFile(skills.FS, path.Join(d.Name(), "SKILL.md"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name(), err)
		}
		var meta struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
		}
		front, ok := frontMatter(data)
		if !ok || yaml.Unmarshal(front, &meta) != nil || meta.Name != d.Name() {
			return nil, fmt.Errorf("%s: SKILL.md needs front matter with name: %s", d.Name(), d.Name())
		}
		s := skill{Name: meta.Name, Description: meta.Description}
		err = fs.WalkDir(skills.FS, d.Name(), func(p string, e fs.DirEntry, err error) error {
			if err == nil && !e.IsDir() {
				s.Files = append(s.Files, strings.TrimPrefix(p, d.Name()+"/"))
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(s.Files)
		out = append(out, s)
	}
	return out, nil
}

func frontMatter(data []byte) ([]byte, bool) {
	rest, ok := bytes.CutPrefix(data, []byte("---\n"))
	if !ok {
		return nil, false
	}
	front, _, ok := bytes.Cut(rest, []byte("\n---"))
	return front, ok
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

func skillsCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, skillsUsage)
		return 2
	}
	all, err := loadSkills()
	if err != nil {
		fmt.Fprintln(stderr, "skills:", err)
		return 1
	}
	byName := map[string]skill{}
	for _, s := range all {
		byName[s.Name] = s
	}

	switch args[0] {
	case "list":
		w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		for _, s := range all {
			fmt.Fprintf(w, "%s\t%s\n", s.Name, firstSentence(s.Description))
		}
		w.Flush()
		return 0
	case "show":
		if len(args) < 2 || len(args) > 3 {
			fmt.Fprint(stderr, skillsUsage)
			return 2
		}
		s, ok := byName[args[1]]
		if !ok {
			fmt.Fprintf(stderr, "skills: no skill %q (see registry-pass skills list)\n", args[1])
			return 1
		}
		file := "SKILL.md"
		if len(args) == 3 {
			file = path.Clean(args[2])
		}
		data, err := fs.ReadFile(skills.FS, path.Join(s.Name, file))
		if err != nil || !fs.ValidPath(file) {
			fmt.Fprintf(stderr, "skills: %s has no file %q (files: %s)\n", s.Name, file, strings.Join(s.Files, ", "))
			return 1
		}
		stdout.Write(data)
		return 0
	case "install":
		return installSkills(args[1:], all, byName, stdout, stderr)
	}
	fmt.Fprintf(stderr, "skills: unknown command %q\n%s", args[0], skillsUsage)
	return 2
}

func installSkills(args []string, all []skill, byName map[string]skill, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("skills install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "your agent's skills directory (required)")
	force := flags.Bool("force", false, "overwrite files that differ")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	// No default: where skills go depends on which agent reads them.
	if *dir == "" {
		fmt.Fprint(stderr, "skills: --dir is required: the skills directory of the agent that will read them\n")
		return 2
	}
	chosen := all
	if names := flags.Args(); len(names) > 0 {
		chosen = nil
		for _, n := range names {
			s, ok := byName[n]
			if !ok {
				fmt.Fprintf(stderr, "skills: no skill %q\n", n)
				return 1
			}
			chosen = append(chosen, s)
		}
	}

	type write struct {
		dst  string
		data []byte
	}
	var writes, conflicts []write
	for _, s := range chosen {
		for _, f := range s.Files {
			data, err := fs.ReadFile(skills.FS, path.Join(s.Name, f))
			if err != nil {
				fmt.Fprintln(stderr, "skills:", err)
				return 1
			}
			w := write{dst: filepath.Join(*dir, s.Name, filepath.FromSlash(f)), data: data}
			if old, err := os.ReadFile(w.dst); err == nil {
				if bytes.Equal(old, data) {
					continue
				}
				conflicts = append(conflicts, w)
			} else if !errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(stderr, "skills:", err)
				return 1
			}
			writes = append(writes, w)
		}
	}
	if len(conflicts) > 0 && !*force {
		fmt.Fprintln(stderr, "skills: these files differ from the built-in version; nothing was written (use --force to overwrite):")
		for _, c := range conflicts {
			fmt.Fprintln(stderr, "  "+c.dst)
		}
		return 1
	}
	for _, w := range writes {
		if err := os.MkdirAll(filepath.Dir(w.dst), 0o755); err != nil {
			fmt.Fprintln(stderr, "skills:", err)
			return 1
		}
		if err := os.WriteFile(w.dst, w.data, 0o644); err != nil {
			fmt.Fprintln(stderr, "skills:", err)
			return 1
		}
	}
	names := make([]string, len(chosen))
	for i, s := range chosen {
		names[i] = s.Name
	}
	fmt.Fprintf(stdout, "installed %s into %s (%d files written)\n", strings.Join(names, ", "), *dir, len(writes))
	return 0
}
