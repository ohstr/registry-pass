package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runSkills(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := skillsCmd(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

var wantSkills = []string{"registry-pass-clients", "registry-pass-grants", "registry-pass-membership", "registry-pass-operate"}

func TestSkillsList(t *testing.T) {
	code, out, _ := runSkills("list")
	if code != 0 {
		t.Fatal("list failed")
	}
	for _, n := range wantSkills {
		if !strings.Contains(out, n) {
			t.Errorf("list missing %s", n)
		}
	}
	all, err := loadSkills()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if len(s.Description) < 80 || !strings.Contains(s.Description, "Use when") {
			t.Errorf("%s: description must say what it does and when to use it", s.Name)
		}
	}
}

func TestSkillsShow(t *testing.T) {
	if code, out, _ := runSkills("show", "registry-pass-grants"); code != 0 || !strings.Contains(out, "reserve: false") {
		t.Fatal("show SKILL.md")
	}
	if code, out, _ := runSkills("show", "registry-pass-operate", "references/config.md"); code != 0 || !strings.Contains(out, "rateLimit:") {
		t.Fatal("show a reference file")
	}
	for _, args := range [][]string{
		{"show", "nope"},
		{"show", "registry-pass-grants", "missing.md"},
		{"show", "registry-pass-grants", "../registry-pass-operate/SKILL.md"},
		{"show", "registry-pass-grants", "/etc/passwd"},
	} {
		if code, _, _ := runSkills(args...); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
	for _, args := range [][]string{{}, {"show"}, {"bogus"}} {
		if code, _, _ := runSkills(args...); code != 2 {
			t.Errorf("%v: want usage error", args)
		}
	}
}

func TestSkillsInstall(t *testing.T) {
	dir := t.TempDir()
	if code, out, e := runSkills("install", "--dir", dir); code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("install: %s", e)
	}
	for _, n := range wantSkills {
		if _, err := os.Stat(filepath.Join(dir, n, "SKILL.md")); err != nil {
			t.Fatalf("%s not installed", n)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "registry-pass-operate", "references", "config.md")); err != nil {
		t.Fatal("references not installed")
	}
	if _, out, _ := runSkills("install", "--dir", dir); !strings.Contains(out, "0 files written") {
		t.Fatalf("reinstall rewrote files: %s", out)
	}

	edited := filepath.Join(dir, "registry-pass-grants", "SKILL.md")
	os.WriteFile(edited, []byte("local notes"), 0o644)
	os.Remove(filepath.Join(dir, "registry-pass-clients", "SKILL.md"))
	if code, _, e := runSkills("install", "--dir", dir); code != 1 || !strings.Contains(e, edited) {
		t.Fatalf("a locally edited file must abort the install: %s", e)
	}
	if _, err := os.Stat(filepath.Join(dir, "registry-pass-clients", "SKILL.md")); err == nil {
		t.Fatal("an aborted install still wrote files")
	}
	if data, _ := os.ReadFile(edited); string(data) != "local notes" {
		t.Fatal("an aborted install overwrote the edited file")
	}
	if code, _, _ := runSkills("install", "--dir", dir, "--force"); code != 0 {
		t.Fatal("--force")
	}
	if data, _ := os.ReadFile(edited); string(data) == "local notes" {
		t.Fatal("--force did not overwrite")
	}

	one := t.TempDir()
	if code, _, _ := runSkills("install", "--dir", one, "registry-pass-clients"); code != 0 {
		t.Fatal("install one")
	}
	if entries, _ := os.ReadDir(one); len(entries) != 1 {
		t.Fatalf("installed %d skills, want 1", len(entries))
	}
	if code, _, _ := runSkills("install", "--dir", one, "nope"); code != 1 {
		t.Fatal("unknown skill installed")
	}
	if code, _, _ := runSkills("install", "--bogus"); code != 2 {
		t.Fatal("bad flag")
	}
}

func TestSkillsInstallNeedsDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	code, _, e := runSkills("install")
	if code != 2 || !strings.Contains(e, "--dir is required") {
		t.Fatalf("install without --dir: %d %s", code, e)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatal("install without --dir wrote into the home directory")
	}
}

func TestSkillsThroughRun(t *testing.T) {
	if code, out, _ := runCmd(t, t.Context(), "skills", "list"); code != 0 || !strings.Contains(out, "registry-pass-operate") {
		t.Fatal("registry-pass skills list")
	}
}

func TestFrontMatter(t *testing.T) {
	if _, ok := frontMatter([]byte("no front matter")); ok {
		t.Fatal("frontMatter")
	}
	if firstSentence("One. Two.") != "One." || firstSentence("One") != "One" {
		t.Fatal("firstSentence")
	}
}
