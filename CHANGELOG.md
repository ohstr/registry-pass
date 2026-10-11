# Changelog

## [0.2.0]

### Added

- Adds `reserve: false` on a grant, so a CI or agent key can be given access to
  a member's own namespace without the name being reserved and the member
  locked out of it.

### Fixed

- Fixes `config print` showing where a list came from on the line of the next
  setting instead of the list's own.

## [0.1.0]

First release: Distribution token authentication with signed Nostr logins
and authority-signed membership.

### Added

- Adds the `/token` endpoint: clients log in with their npub and a signed
  login event, and get a JWT that Distribution 2.8 and v3 both verify. (#2)
- Adds membership from events signed by authority keys, read from relays
  (with NIP-42 AUTH through a key, bunker or socket signer), files or HTTP
  feeds; revocation takes effect at the next token. (#2)
- Adds grants: per-member namespaces, per-key grants, static Basic users,
  anonymous grants, catalog access and a deny list, reloaded without restart. (#2)
- Adds `docker-credential-registry-pass`, a credential helper that signs
  login events with a key file, an environment variable, a NIP-46 bunker or a
  local socket signer. (#2)
- Adds `config check`, `config print`, `config env` and `keygen`; every
  setting has a default and an environment override. (#2)
- Adds health, readiness and Prometheus metrics endpoints, per-IP and
  per-pubkey rate limits, a distroless image and a Helm chart. (#2)
