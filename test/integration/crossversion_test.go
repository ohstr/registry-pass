package integration

import (
	"crypto"
	"crypto/x509"
	"os"
	"testing"
	"time"

	v3token "github.com/distribution/distribution/v3/registry/auth/token"
	v2token "github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
	"github.com/go-jose/go-jose/v4"
	"github.com/ohstr/registry-pass/internal/grants"
	"github.com/ohstr/registry-pass/internal/token"
)

// issuerFor builds an issuer over registry-pass's key with the given
// header options.
func issuerFor(t *testing.T, p *pass, x5c bool, kid string) *token.Issuer {
	key, _ := os.ReadFile(p.keyPEM)
	cert, _ := os.ReadFile(p.certPEM)
	iss, err := token.New(key, cert, nil, token.Options{Issuer: "registry-pass", Algorithm: "ES256", X5C: x5c, KID: kid})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

// TestTokensVerifyWithBothDistributionVersions checks registry-pass tokens
// with Distribution 2.8.3's and v3's own verification code, for every
// header layout: x5c, and kid alone in each version's format.
func TestTokensVerifyWithBothDistributionVersions(t *testing.T) {
	p := startPass(t, passOpts{})
	cert := readCert(t, p.certPEM)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	pub := cert.PublicKey.(crypto.PublicKey)
	access := []grants.Access{{Type: "repository", Name: "alice/app", Actions: []string{"pull"}}}

	ltKey, err := libtrust.FromCryptoPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ourLibtrust, _ := token.LibtrustKeyID(pub)
	if ltKey.KeyID() != ourLibtrust {
		t.Fatalf("libtrust kid %s, ours %s", ltKey.KeyID(), ourLibtrust)
	}
	if v3token.GetJWKThumbprint(pub) != token.Thumbprint(pub) {
		t.Fatal("thumbprint differs from Distribution v3's")
	}

	v2opts := v2token.VerifyOptions{TrustedIssuers: []string{"registry-pass"}, AcceptedAudiences: []string{service},
		Roots: roots, TrustedKeys: map[string]libtrust.PublicKey{ltKey.KeyID(): ltKey}}
	v3opts := v3token.VerifyOptions{TrustedIssuers: []string{"registry-pass"}, AcceptedAudiences: []string{service},
		Roots: roots, TrustedKeys: map[string]crypto.PublicKey{v3token.GetJWKThumbprint(pub): pub}}

	issue := func(iss *token.Issuer) string {
		tok, err := iss.Issue(alice.Pub, service, access, time.Now().Add(5*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		return tok.Raw
	}
	v2ok := func(raw string) error {
		tk, err := v2token.NewToken(raw)
		if err != nil {
			return err
		}
		return tk.Verify(v2opts)
	}
	v3ok := func(raw string) error {
		tk, err := v3token.NewToken(raw, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			return err
		}
		_, err = tk.Verify(v3opts)
		return err
	}

	// The default layout (x5c + v3 kid) and the server's real tokens
	// verify with both versions.
	real := p.tokenFor(t, p.creds(alice), "repository:alice/app:pull")
	for name, raw := range map[string]string{
		"server token":     real,
		"x5c + thumbprint": issue(issuerFor(t, p, true, "auto")),
		"x5c only":         issue(issuerFor(t, p, true, "none")),
		"x5c + libtrust":   issue(issuerFor(t, p, true, "libtrust")),
	} {
		if err := v2ok(raw); err != nil {
			t.Errorf("%s: Distribution 2.8.3 refused: %v", name, err)
		}
		if err := v3ok(raw); err != nil {
			t.Errorf("%s: Distribution v3 refused: %v", name, err)
		}
	}
	// Without x5c, each version needs its own kid format.
	if err := v2ok(issue(issuerFor(t, p, false, "libtrust"))); err != nil {
		t.Errorf("libtrust kid: 2.8.3 refused: %v", err)
	}
	if err := v3ok(issue(issuerFor(t, p, false, "thumbprint"))); err != nil {
		t.Errorf("thumbprint kid: v3 refused: %v", err)
	}

	// Both refuse a token verified against roots that don't include our
	// certificate.
	other := x509.NewCertPool()
	_, attackerCert := selfSigned(t)
	other.AddCert(attackerCert)
	v2opts.Roots, v2opts.TrustedKeys = other, nil
	v3opts.Roots, v3opts.TrustedKeys = other, nil
	if v2ok(real) == nil || v3ok(real) == nil {
		t.Fatal("token verified against foreign roots")
	}
}
