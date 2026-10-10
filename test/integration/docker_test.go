package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
)

// These tests run the real registry images and the real docker CLI. They
// skip when docker is unavailable or RP_SKIP_DOCKER is set.

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("RP_SKIP_DOCKER") != "" {
		t.Skip("RP_SKIP_DOCKER set")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker unavailable")
	}
}

func docker(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

const ipFormat = "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"

// startRegistryContainer runs image in token mode trusting registry-pass's
// certificate. It returns the address this process reaches it at (tests may
// themselves run in a container, so the bridge IP is tried too) and the
// port published on the docker host's loopback.
func startRegistryContainer(t *testing.T, p *pass, image string) (direct, published string) {
	t.Helper()
	// docker cp rather than a bind mount: the test may run in a container
	// whose files the docker host can't see.
	id, err := docker(t, nil, "create", "-p", "127.0.0.1::5000",
		"-e", "REGISTRY_AUTH=token",
		"-e", "REGISTRY_AUTH_TOKEN_REALM="+p.realm,
		"-e", "REGISTRY_AUTH_TOKEN_SERVICE="+service,
		"-e", "REGISTRY_AUTH_TOKEN_ISSUER=registry-pass",
		"-e", "REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/pass.crt",
		"-e", "REGISTRY_STORAGE_DELETE_ENABLED=true",
		image)
	if err != nil {
		t.Fatalf("docker create %s: %v %s", image, err, id)
	}
	t.Cleanup(func() { docker(t, nil, "rm", "-f", id) })
	if out, err := docker(t, nil, "cp", p.certPEM, id+":/pass.crt"); err != nil {
		t.Fatalf("docker cp: %v %s", err, out)
	}
	if out, err := docker(t, nil, "start", id); err != nil {
		t.Fatalf("docker start: %v %s", err, out)
	}
	port, err := docker(t, nil, "port", id, "5000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	published = strings.Split(port, "\n")[0]
	ips, err := docker(t, nil, "inspect", "-f", ipFormat, id)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []string{published}
	for _, ip := range strings.Fields(ips) {
		candidates = append(candidates, ip+":5000")
	}
	client := http.Client{Timeout: time.Second}
	waitFor(t, 30*time.Second, func() bool {
		for _, c := range candidates {
			resp, err := client.Get("http://" + c + "/v2/")
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				direct = c
				return true
			}
		}
		return false
	})
	return direct, published
}

// ownIP returns this process's address as seen from the docker network.
func ownIP(t *testing.T, towards string) string {
	c, err := net.Dial("udp", towards)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

// TestRealRegistryImages runs the acceptance flow against the official
// registry:2.8.3 and registry:3.0.0 images.
func TestRealRegistryImages(t *testing.T) {
	needDocker(t)
	for _, image := range []string{"registry:2.8.3", "registry:3.0.0"} {
		t.Run(image, func(t *testing.T) {
			p := startPass(t, passOpts{})
			reg, _ := startRegistryContainer(t, p, image)
			img := randomImage(t, 3)
			if err := push(t, reg, "alice/app:v1", img, p.creds(alice)); err != nil {
				t.Fatalf("member push: %v", err)
			}
			if _, err := pull(t, reg, "alice/app:v1", p.creds(alice)); err != nil {
				t.Fatalf("member pull: %v", err)
			}
			mustDenied(t, "push outside the namespace", push(t, reg, "bob/app:v1", img, p.creds(alice)))
			static := &authn.Basic{Username: "node-pull", Password: staticPassword}
			if _, err := pull(t, reg, "alice/app:v1", static); err != nil {
				t.Fatalf("static pull: %v", err)
			}
			mustDenied(t, "static push", push(t, reg, "alice/app:v2", img, static))

			// The registry itself refuses a token signed by another key.
			attackerKey, attackerCert := selfSigned(t)
			forged := sign(t, attackerKey, map[string]any{"x5c": []string{base64.StdEncoding.EncodeToString(attackerCert.Raw)}},
				claimsFor("alice/app", "pull"))
			if code := getManifest(t, reg, "alice/app", forged); code != http.StatusUnauthorized {
				t.Fatalf("forged token: %d", code)
			}
			if code := getManifest(t, reg, "alice/app", p.tokenFor(t, p.creds(alice), "repository:alice/app:pull")); code != 200 {
				t.Fatalf("real token: %d", code)
			}

			p.setMembers(authority.Member(30078, "member:", "alice", alice.Pub, "dead", time.Now()))
			waitFor(t, 10*time.Second, func() bool { return p.app.Store.Lookup(alice.Pub).Name == "" })
			mustDenied(t, "push after revocation", push(t, reg, "alice/app:v3", img, p.creds(alice)))
		})
	}
}

// TestDockerCLIWithCredentialHelper pushes and pulls with the unmodified
// docker CLI, which gets its credentials from docker-credential-registry-pass.
func TestDockerCLIWithCredentialHelper(t *testing.T) {
	needDocker(t)
	if runtime.GOOS != "linux" {
		t.Skip("needs a linux docker host")
	}
	// The daemon, not this process, calls registry-pass: give it an
	// address on the docker network.
	probe, _ := startRegistryContainer(t, startPass(t, passOpts{}), "registry:2.8.3")
	p := startPass(t, passOpts{realmHost: ownIP(t, probe)})
	_, reg := startRegistryContainer(t, p, "registry:3.0.0")

	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "docker-credential-registry-pass"), "github.com/ohstr/registry-pass/cmd/docker-credential-registry-pass")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v %s", err, out)
	}
	keyPath := filepath.Join(t.TempDir(), "alice.nsec")
	os.WriteFile(keyPath, []byte(alice.Nsec), 0o600)
	helperCfg := filepath.Join(t.TempDir(), "helper.yaml")
	os.WriteFile(helperCfg, []byte(fmt.Sprintf("cacheDir: %s\nregistries:\n  %s:\n    realm: %s\n    service: %s\n    signer: file://%s\n",
		filepath.Join(t.TempDir(), "cache"), reg, p.realm, service, keyPath)), 0o600)
	dockerCfg := t.TempDir()
	cfg, _ := json.Marshal(map[string]any{"credHelpers": map[string]string{reg: "registry-pass"}})
	os.WriteFile(filepath.Join(dockerCfg, "config.json"), cfg, 0o600)
	env := []string{"DOCKER_CONFIG=" + dockerCfg, "PATH=" + bin + ":" + os.Getenv("PATH"), "DOCKER_CREDENTIAL_REGISTRY_PASS_CONFIG=" + helperCfg}

	own := reg + "/alice/app:v1"
	other := reg + "/bob/app:v1"
	for _, tag := range []string{own, other} {
		if out, err := docker(t, nil, "tag", "registry:2.8.3", tag); err != nil {
			t.Fatalf("tag: %v %s", err, out)
		}
		t.Cleanup(func() { docker(t, nil, "rmi", tag) })
	}
	if out, err := docker(t, env, "push", own); err != nil {
		t.Fatalf("docker push to own namespace: %v\n%s", err, out)
	}
	out, err := docker(t, env, "push", other)
	if err == nil {
		t.Fatal("docker push outside the namespace succeeded")
	}
	if !strings.Contains(strings.ToLower(out), "denied") && !strings.Contains(strings.ToLower(out), "unauthorized") {
		t.Fatalf("unexpected push error: %s", out)
	}
	docker(t, nil, "rmi", own)
	if out, err := docker(t, env, "pull", own); err != nil {
		t.Fatalf("docker pull: %v\n%s", err, out)
	}
	// docker logout goes through erase, which is a no-op.
	if out, err := docker(t, env, "logout", reg); err != nil {
		t.Fatalf("docker logout: %v %s", err, out)
	}
}
