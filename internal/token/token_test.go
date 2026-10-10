package token

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ohstr/registry-pass/internal/grants"
)

func issuer(t *testing.T, alg string, mod func(*Options)) (*Issuer, []byte) {
	t.Helper()
	keyPEM, certPEM, err := Generate(alg, "registry-pass", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Issuer: "registry-pass", Algorithm: alg, X5C: true, KID: "auto"}
	if mod != nil {
		mod(&o)
	}
	iss, err := New(keyPEM, certPEM, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	return iss, certPEM
}

func certKey(t *testing.T, certPEM []byte) any {
	block, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.PublicKey
}

func decodeSegment(t *testing.T, raw string, i int) map[string]any {
	part := strings.Split(raw, ".")[i]
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssueVerifiesWithCertificateKey(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			iss, certPEM := issuer(t, alg, nil)
			access := []grants.Access{{Type: "repository", Name: "alice/app", Actions: []string{"pull", "push"}}}
			exp := time.Now().Add(5 * time.Minute)
			tok, err := iss.Issue("abc", "registry.example", access, exp)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := jwt.Parse(tok.Raw, func(*jwt.Token) (any, error) { return certKey(t, certPEM), nil },
				jwt.WithValidMethods([]string{alg}), jwt.WithAudience("registry.example"), jwt.WithIssuer("registry-pass"))
			if err != nil || !parsed.Valid {
				t.Fatalf("token does not verify: %v", err)
			}
			hdr := decodeSegment(t, tok.Raw, 0)
			if hdr["typ"] != "JWT" || hdr["alg"] != alg || hdr["kid"] != iss.KeyID() {
				t.Fatalf("header %v", hdr)
			}
			x5c, _ := hdr["x5c"].([]any)
			block, _ := pem.Decode(certPEM)
			if len(x5c) != 1 || x5c[0] != base64.StdEncoding.EncodeToString(block.Bytes) {
				t.Fatal("x5c must carry the certificate, standard base64 DER")
			}
			claims := decodeSegment(t, tok.Raw, 1)
			if _, isString := claims["aud"].(string); !isString {
				t.Fatal("aud must be a string for Distribution 2.8")
			}
			if claims["sub"] != "abc" || int64(claims["exp"].(float64)) != exp.Unix() || claims["jti"] == "" {
				t.Fatalf("claims %v", claims)
			}
			acc := claims["access"].([]any)[0].(map[string]any)
			if acc["name"] != "alice/app" || len(acc["actions"].([]any)) != 2 {
				t.Fatalf("access %v", acc)
			}
		})
	}
}

func TestTokenDetails(t *testing.T) {
	iss, _ := issuer(t, "ES256", nil)
	a, _ := iss.Issue("s", "r", nil, time.Now().Add(time.Minute))
	b, _ := iss.Issue("s", "r", nil, time.Now().Add(time.Minute))
	if a.ID == b.ID {
		t.Fatal("jti must be random")
	}
	if acc := decodeSegment(t, a.Raw, 1)["access"]; acc == nil {
		t.Fatal("access must be an empty list, not null")
	}
	if _, err := iss.Issue("s", "r", nil, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expired token issued")
	}

	noX5C, _ := issuer(t, "ES256", func(o *Options) { o.X5C = false; o.KID = "libtrust" })
	tok, _ := noX5C.Issue("s", "r", nil, time.Now().Add(time.Minute))
	hdr := decodeSegment(t, tok.Raw, 0)
	if _, ok := hdr["x5c"]; ok {
		t.Fatal("x5c present though disabled")
	}
	if !regexp.MustCompile(`^([A-Z2-7]{4}:){11}[A-Z2-7]{4}$`).MatchString(hdr["kid"].(string)) {
		t.Fatalf("libtrust kid format: %v", hdr["kid"])
	}
	none, _ := issuer(t, "ES256", func(o *Options) { o.KID = "none" })
	tok, _ = none.Issue("s", "r", nil, time.Now().Add(time.Minute))
	if _, ok := decodeSegment(t, tok.Raw, 0)["kid"]; ok {
		t.Fatal("kid present though none")
	}
	if iss.NotAfter().Before(time.Now().Add(23 * time.Hour)) {
		t.Fatal("NotAfter")
	}
}

func TestThumbprintFormat(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tp := Thumbprint(&k.PublicKey)
	if len(tp) != 43 || strings.ContainsAny(tp, "+/=") {
		t.Fatalf("thumbprint %q", tp)
	}
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	if Thumbprint(&r.PublicKey) == "" || Thumbprint(ed25519.PublicKey(make([]byte, 32))) != "" {
		t.Fatal("thumbprint key types")
	}
	if len(bigEndian(65537)) != 3 {
		t.Fatal("bigEndian")
	}
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestRefusesBadKeysAndCertificates(t *testing.T) {
	keyA, certA, _ := Generate("ES256", "a", time.Hour)
	_, certB, _ := Generate("ES256", "b", time.Hour)
	ok := Options{Issuer: "i", Algorithm: "ES256", X5C: true, KID: "auto"}

	if _, err := New(keyA, certB, nil, ok); err == nil {
		t.Error("certificate of another key accepted")
	}
	if _, err := New(keyA, certA, nil, Options{Issuer: "i", Algorithm: "ES384", KID: "auto"}); err == nil {
		t.Error("ES384 with a P-256 key accepted")
	}
	if _, err := New(keyA, certA, nil, Options{Issuer: "i", Algorithm: "RS256", KID: "auto"}); err == nil {
		t.Error("RS256 with an EC key accepted")
	}
	later := ok
	later.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := New(keyA, certA, nil, later); err == nil {
		t.Error("expired certificate accepted")
	}
	earlier := ok
	earlier.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	if _, err := New(keyA, certA, nil, earlier); err == nil {
		t.Error("not-yet-valid certificate accepted")
	}
	if _, err := New(keyA, []byte("nope"), nil, ok); err == nil {
		t.Error("no certificate accepted")
	}
	if _, err := New(keyA, certA, []byte("nope"), ok); err == nil {
		t.Error("bad chain accepted")
	}
	if _, err := New(keyA, certA, certB, ok); err != nil {
		t.Errorf("chain appended: %v", err)
	}

	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := methodFor("RS256", small); err == nil {
		t.Error("1024-bit RSA accepted")
	}
	for name, data := range map[string][]byte{
		"garbage":   []byte("not pem"),
		"encrypted": pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}),
		"proc-type": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}}),
		"junk der":  pemOf("PRIVATE KEY", []byte{1, 2, 3}),
	} {
		if _, err := ParsePrivateKey(data); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	if _, err := ParsePrivateKey(pemOf("PRIVATE KEY", der)); err == nil {
		t.Error("Ed25519 key accepted")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(ec)
	if _, err := ParsePrivateKey(pemOf("EC PRIVATE KEY", sec1)); err != nil {
		t.Errorf("SEC 1 key refused: %v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ParsePrivateKey(pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk))); err != nil {
		t.Errorf("PKCS#1 key refused: %v", err)
	}
	if _, _, err := Generate("HS256", "x", time.Hour); err == nil {
		t.Error("HS256 keygen accepted")
	}
}
