package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/token"
)

type tokenParts struct {
	header map[string]any
	claims map[string]any
}

func readCert(t *testing.T, path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func passKey(t *testing.T, p *pass) crypto.Signer {
	data, _ := os.ReadFile(p.keyPEM)
	k, err := token.ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func claimsFor(repo string, actions ...string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": "registry-pass", "sub": alice.Pub, "aud": service,
		"exp": now.Add(5 * time.Minute).Unix(), "nbf": now.Unix(), "iat": now.Unix(), "jti": "x",
		"access": []grants.Access{{Type: "repository", Name: repo, Actions: actions}},
	}
}

func sign(t *testing.T, key crypto.Signer, header map[string]any, claims map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	for k, v := range header {
		tok.Header[k] = v
	}
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func b64json(v any) string {
	data, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(data)
}

// selfSigned is an attacker's key and a self-signed certificate for it.
func selfSigned(t *testing.T) (crypto.Signer, *x509.Certificate) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return k, c
}

func getManifest(t *testing.T, reg, repo, bearer string) int {
	req, _ := http.NewRequest("GET", "http://"+reg+"/v2/"+repo+"/manifests/v1", nil)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestForgedTokensRejectedByRegistry(t *testing.T) {
	p := startPass(t, passOpts{})
	reg := startRegistryV3(t, p)
	if err := push(t, reg, "alice/app:v1", randomImage(t, 1), p.creds(alice)); err != nil {
		t.Fatal(err)
	}
	if err := push(t, reg, "alice/other:v1", randomImage(t, 1), p.creds(alice)); err != nil {
		t.Fatal(err)
	}

	ourKey := passKey(t, p)
	ourCert := readCert(t, p.certPEM)
	ourX5C := []string{base64.StdEncoding.EncodeToString(ourCert.Raw)}
	attackerKey, attackerCert := selfSigned(t)
	attackerX5C := []string{base64.StdEncoding.EncodeToString(attackerCert.Raw)}

	// Control: a real token from registry-pass works.
	valid := p.tokenFor(t, p.creds(alice), "repository:alice/app:pull")
	if code := getManifest(t, reg, "alice/app", valid); code != 200 {
		t.Fatalf("control: valid token got %d", code)
	}
	if code := getManifest(t, reg, "alice/app", sign(t, ourKey, map[string]any{"x5c": ourX5C}, claimsFor("alice/app", "pull"))); code != 200 {
		t.Fatalf("control: hand-signed token with our key got %d", code)
	}

	parts := strings.Split(valid, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := strings.Replace(string(payload), "alice/app", "alice/other", 1)
	hs := func(secret []byte, header map[string]any) string {
		h := b64json(header) + "." + b64json(claimsFor("alice/app", "pull"))
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(h))
		return h + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(ourKey.Public())
	expired := claimsFor("alice/app", "pull")
	expired["exp"] = time.Now().Add(-2 * time.Minute).Unix()
	wrongAud := claimsFor("alice/app", "pull")
	wrongAud["aud"] = "other.registry"
	wrongIss := claimsFor("alice/app", "pull")
	wrongIss["iss"] = "attacker"
	jwkHeader := map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(attackerKey.Public().(*ecdsa.PublicKey).X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(attackerKey.Public().(*ecdsa.PublicKey).Y.Bytes())}}

	attacks := map[string]string{
		"attacker key, attacker cert in x5c": sign(t, attackerKey, map[string]any{"x5c": attackerX5C}, claimsFor("alice/app", "pull")),
		"attacker key, our cert in x5c":      sign(t, attackerKey, map[string]any{"x5c": ourX5C}, claimsFor("alice/app", "pull")),
		"attacker key, our kid":              sign(t, attackerKey, map[string]any{"kid": token.Thumbprint(ourKey.Public())}, claimsFor("alice/app", "pull")),
		"attacker key in an embedded jwk":    sign(t, attackerKey, jwkHeader, claimsFor("alice/app", "pull")),
		"alg none": b64json(map[string]any{"alg": "none", "typ": "JWT", "x5c": ourX5C}) + "." +
			b64json(claimsFor("alice/app", "pull")) + ".",
		"HS256 keyed with our certificate": hs(ourCert.Raw, map[string]any{"alg": "HS256", "typ": "JWT", "x5c": ourX5C}),
		"HS256 keyed with our public key":  hs(pubDER, map[string]any{"alg": "HS256", "typ": "JWT", "kid": token.Thumbprint(ourKey.Public())}),
		"payload tampered after signing":   parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(tampered)) + "." + parts[2],
		"signature stripped":               parts[0] + "." + parts[1] + ".",
		"expired beyond leeway":            sign(t, ourKey, map[string]any{"x5c": ourX5C}, expired),
		"other audience":                   sign(t, ourKey, map[string]any{"x5c": ourX5C}, wrongAud),
		"other issuer":                     sign(t, ourKey, map[string]any{"x5c": ourX5C}, wrongIss),
		"garbage":                          "not.a.jwt",
	}
	for name, raw := range attacks {
		target := "alice/app"
		if name == "payload tampered after signing" {
			target = "alice/other"
		}
		if code := getManifest(t, reg, target, raw); code != http.StatusUnauthorized {
			t.Errorf("%s: registry answered %d, want 401", name, code)
		}
	}

	// A real token for one repository doesn't open another.
	if code := getManifest(t, reg, "alice/other", valid); code != http.StatusUnauthorized {
		t.Errorf("token scoped to alice/app opened alice/other: %d", code)
	}
	// A real token whose scope was refused grants nothing.
	nothing := p.tokenFor(t, p.creds(bob), "repository:alice/app:pull")
	if code := getManifest(t, reg, "alice/app", nothing); code != http.StatusUnauthorized {
		t.Errorf("empty-access token read alice/app: %d", code)
	}
}
