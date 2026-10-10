// Package token issues the registry tokens (PLAN.md §4): JWTs signed with
// the configured key, carrying the certificate chain in x5c so both
// Distribution 2.8 and v3 can verify them against their rootcertbundle.
package token

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ohstr/registry-pass/internal/grants"
)

// Options configures an Issuer.
type Options struct {
	Issuer    string
	Algorithm string // ES256 | ES384 | RS256
	X5C       bool
	KID       string // auto | libtrust | thumbprint | none
	Now       func() time.Time
}

// Issuer signs registry tokens.
type Issuer struct {
	opts   Options
	key    crypto.Signer
	method jwt.SigningMethod
	chain  []*x509.Certificate
	x5c    []string
	kid    string
}

// New builds an Issuer from PEM data. chainPEM may be empty.
func New(keyPEM, certPEM, chainPEM []byte, opts Options) (*Issuer, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	certs, err := parseCerts(certPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if len(chainPEM) > 0 {
		more, err := parseCerts(chainPEM)
		if err != nil {
			return nil, fmt.Errorf("chain: %w", err)
		}
		certs = append(certs, more...)
	}
	leaf := certs[0]
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		return nil, errors.New("the certificate does not match the signing key")
	}
	method, err := methodFor(opts.Algorithm, key)
	if err != nil {
		return nil, err
	}
	now := opts.Now()
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	iss := &Issuer{opts: opts, key: key, method: method, chain: certs}
	for _, c := range certs {
		iss.x5c = append(iss.x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	switch opts.KID {
	case "auto", "thumbprint":
		iss.kid = Thumbprint(key.Public())
	case "libtrust":
		iss.kid, err = LibtrustKeyID(key.Public())
		if err != nil {
			return nil, err
		}
	}
	return iss, nil
}

// NotAfter is when the signing certificate expires.
func (i *Issuer) NotAfter() time.Time { return i.chain[0].NotAfter }

// KeyID is the kid header value ("" when none).
func (i *Issuer) KeyID() string { return i.kid }

// Token is an issued token.
type Token struct {
	Raw       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	ID        string
}

// Issue signs a token for subject sub on service aud, granting access,
// valid until exp.
func (i *Issuer) Issue(sub, aud string, access []grants.Access, exp time.Time) (Token, error) {
	return i.IssueAt(i.opts.Now(), sub, aud, access, exp)
}

// IssueAt is Issue with the issue time given, so callers computing exp
// from their own clock reading report a consistent lifetime.
func (i *Issuer) IssueAt(now time.Time, sub, aud string, access []grants.Access, exp time.Time) (Token, error) {
	now, exp = now.Truncate(time.Second), exp.Truncate(time.Second)
	if !exp.After(now) {
		return Token{}, errors.New("token expiry is not in the future")
	}
	if access == nil {
		access = []grants.Access{}
	}
	jti, err := randomID()
	if err != nil {
		return Token{}, err
	}
	claims := jwt.MapClaims{
		"iss":    i.opts.Issuer,
		"sub":    sub,
		"aud":    aud, // a string: Distribution 2.8 can't decode an array
		"exp":    exp.Unix(),
		"nbf":    now.Unix(),
		"iat":    now.Unix(),
		"jti":    jti,
		"access": access,
	}
	t := jwt.NewWithClaims(i.method, claims)
	if i.opts.X5C {
		t.Header["x5c"] = i.x5c
	}
	if i.kid != "" {
		t.Header["kid"] = i.kid
	}
	raw, err := t.SignedString(i.key)
	if err != nil {
		return Token{}, err
	}
	return Token{Raw: raw, IssuedAt: now, ExpiresAt: exp, ID: jti}, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func methodFor(alg string, key crypto.Signer) (jwt.SigningMethod, error) {
	switch k := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch {
		case alg == "ES256" && k.Curve == elliptic.P256():
			return jwt.SigningMethodES256, nil
		case alg == "ES384" && k.Curve == elliptic.P384():
			return jwt.SigningMethodES384, nil
		}
		return nil, fmt.Errorf("algorithm %s does not fit an EC %s key", alg, k.Curve.Params().Name)
	case *rsa.PublicKey:
		if alg != "RS256" {
			return nil, fmt.Errorf("algorithm %s does not fit an RSA key", alg)
		}
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA key of %d bits is too small (min 2048)", k.N.BitLen())
		}
		return jwt.SigningMethodRS256, nil
	}
	return nil, errors.New("unsupported key type")
}

// ParsePrivateKey reads a PEM EC or RSA private key (PKCS#8, SEC 1 or
// PKCS#1).
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key: no PEM block")
	}
	if strings.Contains(block.Type, "ENCRYPTED") || block.Headers["Proc-Type"] != "" {
		return nil, errors.New("signing key: encrypted keys are not supported")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			switch s.(type) {
			case *ecdsa.PrivateKey, *rsa.PrivateKey:
				return s, nil
			}
		}
		return nil, errors.New("signing key: only EC and RSA keys are supported")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("signing key: not an EC or RSA private key")
}

func parseCerts(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate found")
	}
	return out, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// Thumbprint is the kid Distribution v3 derives from a rootcertbundle key
// (its GetJWKThumbprint): SHA-256 of the key's JWK members, base64url.
func Thumbprint(pub crypto.PublicKey) string {
	var payload string
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		raw, err := k.Bytes() // 0x04 || X || Y, fixed width
		if err != nil {
			return ""
		}
		n := (len(raw) - 1) / 2
		// Distribution encodes big.Int.Bytes(): no leading zero bytes.
		x := base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(raw[1:1+n], "\x00"))
		y := base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(raw[1+n:], "\x00"))
		payload = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, k.Curve.Params().Name, x, y)
	case *rsa.PublicKey:
		e := base64.RawURLEncoding.EncodeToString(bigEndian(k.E))
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		payload = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)
	default:
		return ""
	}
	sum := sha256.Sum256([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func bigEndian(n int) []byte {
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n)}, b...)
		n >>= 8
	}
	return b
}

// LibtrustKeyID is the kid Distribution 2.8 (libtrust) derives from a key:
// the first 240 bits of SHA-256 over the DER public key, base32, in
// colon-separated groups of four.
func LibtrustKeyID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:30]), "=")
	var groups []string
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:min(i+4, len(s))])
	}
	return strings.Join(groups, ":"), nil
}
