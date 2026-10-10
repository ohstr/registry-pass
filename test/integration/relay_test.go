package integration

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/registry-pass/internal/testkit"
)

// TestRelayMembershipEndToEnd: membership comes from an AUTH-required
// nmilat relay read with a reader key; a revocation published on the
// relay takes effect at the next token.
func TestRelayMembershipEndToEnd(t *testing.T) {
	relayURL := testkit.StartRelay(t, true)
	testkit.Publish(t, relayURL, authority,
		authority.Member(30078, "member:", "alice", alice.Pub, "alive", time.Now().Add(-time.Minute)))
	// A forged record on the same relay must change nothing.
	testkit.Publish(t, relayURL, mallory, mallory.Member(30078, "member:", "mallory", mallory.Pub, "alive", time.Now()))

	p := startPass(t, passOpts{relayURL: relayURL, members: []*nip01.Event{}})
	reg := startRegistryV3(t, p)
	waitFor(t, 10*time.Second, func() bool { return p.app.Store.Lookup(alice.Pub).Name == "alice" })

	auth := p.creds(alice)
	if err := push(t, reg, "alice/app:v1", randomImage(t, 2), auth); err != nil {
		t.Fatalf("push with relay membership: %v", err)
	}
	mustDenied(t, "forged relay record", push(t, reg, "mallory/app:v1", randomImage(t, 1), p.creds(mallory)))

	testkit.Publish(t, relayURL, authority, authority.Member(30078, "member:", "alice", alice.Pub, "dead", time.Now()))
	waitFor(t, 10*time.Second, func() bool { return p.app.Store.Lookup(alice.Pub).Name == "" })
	mustDenied(t, "push after a relay revocation", push(t, reg, "alice/app:v2", randomImage(t, 1), auth))
}
