// Package testkit holds helpers shared by registry-pass's tests: deterministic
// Nostr keys and signed events.
package testkit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/utils"
)

// Key is a Nostr key pair in every encoding tests need.
type Key struct {
	Priv, Pub, Npub, Nsec string
}

// NewKey derives a deterministic key from seed.
func NewKey(seed string) Key {
	sum := sha256.Sum256([]byte("registry-pass-test:" + seed))
	priv := hex.EncodeToString(sum[:])
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		panic(err)
	}
	npub, err := nip19.EncodePublicKey(pub)
	if err != nil {
		panic(err)
	}
	nsec, err := nip19.EncodePrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return Key{Priv: priv, Pub: pub, Npub: npub, Nsec: nsec}
}

// Sign builds and signs an event with k.
func (k Key) Sign(kind int, createdAt time.Time, content string, tags ...[]string) *nip01.Event {
	ev := nip01.NewEvent(kind, content, tags...)
	ev.CreatedAt = uint64(createdAt.Unix())
	if err := ev.Sign(k.Priv); err != nil {
		panic(err)
	}
	return ev
}

// LoginEvent builds a login event for realm, valid from created for life.
func (k Key) LoginEvent(realm string, created time.Time, life time.Duration, extra ...[]string) *nip01.Event {
	tags := [][]string{
		{"u", realm},
		{"method", "GET"},
		{"expiration", strconv.FormatInt(created.Add(life).Unix(), 10)},
	}
	tags = append(tags, extra...)
	return k.Sign(27235, created, "", tags...)
}

// Password encodes ev as a Basic password (base64url of its JSON, unpadded).
func Password(ev *nip01.Event) string {
	data, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// Member builds a membership record signed by authority k.
func (k Key) Member(kind int, prefix, name, pubkey, status string, created time.Time) *nip01.Event {
	content, _ := json.Marshal(map[string]string{"name": name, "pubkey": pubkey, "status": status})
	return k.Sign(kind, created, string(content), []string{"d", prefix + name})
}
