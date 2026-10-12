package quota

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ohstr/registry-pass/internal/grants"
)

// manifestTypes are the manifests the walk understands.
var manifestTypes = []string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v1+prettyjws",
	"application/vnd.docker.distribution.manifest.v1+json",
}

// maxManifestSize bounds a manifest body, as Distribution does (4 MiB).
const maxManifestSize = 4 << 20

// Minter issues a bearer token for registry-pass's own registry calls.
type Minter func(access []grants.Access) (string, error)

// Registry reads the registry API with tokens registry-pass mints for
// itself.
type Registry struct {
	Base   *url.URL
	Client *http.Client
	Mint   Minter
}

var errNotFound = errors.New("not found")

func (r *Registry) do(ctx context.Context, method, path, token string, accept []string) (*http.Response, error) {
	u, err := r.Base.Parse(path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if len(accept) > 0 {
		req.Header.Set("Accept", strings.Join(accept, ", "))
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		resp.Body.Close()
		return nil, errNotFound
	case resp.StatusCode != http.StatusOK:
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: %s", method, u.Path, resp.Status)
	}
	return resp, nil
}

func repoToken(m Minter, repo string) (string, error) {
	return m([]grants.Access{{Type: grants.TypeRepository, Name: repo, Actions: []string{grants.ActionPull}}})
}

// list follows a paginated list (catalog or tags) and returns key's items.
// It leaves the page size to the registry, which refuses an n above its
// own maximum.
func (r *Registry) list(ctx context.Context, path, key, token string) ([]string, error) {
	var out []string
	next := path
	for next != "" {
		resp, err := r.do(ctx, http.MethodGet, next, token, nil)
		if err != nil {
			return out, err
		}
		var page map[string]json.RawMessage
		err = json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&page)
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			return out, fmt.Errorf("%s: %w", path, err)
		}
		var items []string
		if raw, ok := page[key]; ok && string(raw) != "null" {
			if err := json.Unmarshal(raw, &items); err != nil {
				return out, fmt.Errorf("%s: %w", path, err)
			}
		}
		out = append(out, items...)
		next = nextLink(link)
		if len(items) == 0 {
			next = ""
		}
	}
	return out, nil
}

// nextLink reads `<url>; rel="next"`.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		target = strings.TrimSpace(target)
		if strings.HasPrefix(target, "<") && strings.HasSuffix(target, ">") {
			return target[1 : len(target)-1]
		}
	}
	return ""
}

// Catalog lists every repository.
func (r *Registry) Catalog(ctx context.Context) ([]string, error) {
	tok, err := r.Mint([]grants.Access{{Type: grants.TypeRegistry, Name: "catalog", Actions: []string{grants.ActionAll}}})
	if err != nil {
		return nil, err
	}
	return r.list(ctx, "/v2/_catalog", "repositories", tok)
}

// Tags lists a repository's tags; none when the repository is gone.
func (r *Registry) Tags(ctx context.Context, repo, token string) ([]string, error) {
	tags, err := r.list(ctx, "/v2/"+repo+"/tags/list", "tags", token)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	return tags, err
}

// Resolve returns the digest a tag points to; "" when it is gone.
func (r *Registry) Resolve(ctx context.Context, repo, tag, token string) (string, error) {
	resp, err := r.do(ctx, http.MethodHead, "/v2/"+repo+"/manifests/"+tag, token, manifestTypes)
	if errors.Is(err, errNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if d := resp.Header.Get("Docker-Content-Digest"); d != "" {
		return d, nil
	}
	body, err := r.Manifest(ctx, repo, tag, token)
	if err != nil || body == nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Manifest fetches a manifest by tag or digest; nil when it is gone.
func (r *Registry) Manifest(ctx context.Context, repo, ref, token string) ([]byte, error) {
	resp, err := r.do(ctx, http.MethodGet, "/v2/"+repo+"/manifests/"+ref, token, manifestTypes)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxManifestSize {
		return nil, fmt.Errorf("manifest %s@%s is larger than %d bytes", repo, ref, maxManifestSize)
	}
	return body, nil
}

// BlobSize returns a blob's stored size; ok false when the repository
// doesn't hold it.
func (r *Registry) BlobSize(ctx context.Context, repo, digest, token string) (int64, bool, error) {
	resp, err := r.do(ctx, http.MethodHead, "/v2/"+repo+"/blobs/"+digest, token, nil)
	if errors.Is(err, errNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	resp.Body.Close()
	if resp.ContentLength < 0 {
		return 0, false, fmt.Errorf("blob %s@%s: no Content-Length", repo, digest)
	}
	return resp.ContentLength, true, nil
}

// manifestInfo is what the walk keeps of a manifest.
type manifestInfo struct {
	Size     int64    `json:"size"`
	Blobs    []string `json:"blobs,omitempty"`
	Children []string `json:"children,omitempty"`
}

type descriptor struct {
	Digest string `json:"digest"`
}

// parseManifest reads the blobs (config and layers) and child manifests
// a manifest references.
func parseManifest(body []byte) (manifestInfo, error) {
	var m struct {
		Config    *descriptor  `json:"config"`
		Layers    []descriptor `json:"layers"`
		Manifests []descriptor `json:"manifests"`
		FSLayers  []struct {
			BlobSum string `json:"blobSum"`
		} `json:"fsLayers"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return manifestInfo{}, err
	}
	info := manifestInfo{Size: int64(len(body))}
	add := func(list *[]string, d string) {
		for _, x := range *list {
			if x == d {
				return
			}
		}
		*list = append(*list, d)
	}
	for _, c := range m.Manifests {
		add(&info.Children, c.Digest)
	}
	if m.Config != nil && m.Config.Digest != "" {
		add(&info.Blobs, m.Config.Digest)
	}
	for _, l := range m.Layers {
		add(&info.Blobs, l.Digest)
	}
	for _, l := range m.FSLayers {
		add(&info.Blobs, l.BlobSum)
	}
	return info, nil
}
