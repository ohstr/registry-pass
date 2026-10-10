# Changelog

## [0.1.0]

First release: Distribution token authentication with signed Nostr logins
and authority-signed membership.

### Added

- Adds the `/token` endpoint: clients log in with their npub and a signed
  login event, and get a JWT that Distribution 2.8 and v3 both verify.
- Adds membership from events signed by authority keys, read from relays
  (with NIP-42 AUTH through a key, bunker or socket signer), files or HTTP
  feeds; revocation takes effect at the next token.
- Adds grants: per-member namespaces, per-key grants, static Basic users,
  anonymous grants, catalog access and a deny list, reloaded without restart.
- Adds `docker-credential-registry-pass`, a credential helper that signs
  login events with a key file, an environment variable, a NIP-46 bunker or a
  local socket signer.
- Adds `config check`, `config print`, `config env` and `keygen`; every
  setting has a default and an environment override.
- Adds health, readiness and Prometheus metrics endpoints, per-IP and
  per-pubkey rate limits, a distroless image and a Helm chart.
