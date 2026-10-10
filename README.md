# registry-pass

Nostr logins for an OCI registry. registry-pass is a token service for
[Distribution](https://github.com/distribution/distribution) (2.8 and v3):
clients log in with a **signed Nostr event** instead of a password, and get a
short-lived registry token scoped to the repositories their identity may use.
Who is a member comes from events **signed by an authority key**, so whoever
delivers them can't forge them. The registry itself is unmodified.

The design, every setting and its rationale are in [PLAN.md](PLAN.md).

## How it works

```
client ──Basic(npub, signed login event)──▶ registry-pass ──JWT (minutes)──▶ client
client ──Bearer JWT──▶ registry (auth: token, trusts registry-pass's certificate)
registry-pass ◀── membership events (signed by the authority) ── relay / file / http
```

## Quick start

```sh
# 1. A signing key and the certificate the registry will trust.
registry-pass keygen --key-out /run/secrets/pass.key --cert-out pass.crt

# 2. Config and grants (start from deploy/examples/).
registry-pass --config config.yaml config check
registry-pass --config config.yaml config print   # every value and where it came from

# 3. Run it.
registry-pass --config config.yaml serve
```

Registry side (`config.yml` of Distribution):

```yaml
auth:
  token:
    realm: https://pass.example/token
    service: registry.example
    issuer: registry-pass
    rootcertbundle: /etc/registry/pass.crt
```

Clients use the credential helper; add to `~/.docker/config.json`:

```json
{ "credHelpers": { "registry.example": "registry-pass" } }
```

and describe the registry in `~/.config/registry-pass/helper.yaml`
(see [deploy/examples/helper.yaml](deploy/examples/helper.yaml)). The helper
signs with a key file, an `env:` variable, a NIP-46 bunker (`bunker://`) or a
local socket signer (`bunker+unix://`), so the key need not be on the client.

Give registry-pass a DNS name: recent go-containerregistry (crane, kaniko,
ko) refuses token realms on private IP literals.

## Configuration

Everything is a setting with a default: one YAML file, overridden by
`REGISTRY_PASS_*` environment variables (`REGISTRY_PASS_LOGIN__MAX_LIFETIME=2h`;
`registry-pass config env` lists them all). Secrets are read only from files.
An invalid or inconsistent configuration refuses to start. The full reference
is PLAN.md §8; [deploy/examples/](deploy/examples/) has a starting point and
[deploy/helm/](deploy/helm/registry-pass) a chart.

## Operations

- One static binary, a 9 MB distroless image running as non-root
  ([deploy/Dockerfile](deploy/Dockerfile)), no state on disk.
- `/healthz`, `/readyz` (process only, never membership freshness, so static
  users keep working) and `/metrics` (logins by reason, tokens, rate limits,
  membership size and freshness, per-source sync age, relay AUTH state,
  certificate expiry), optionally on a separate admin port.
- Grants reload on SIGHUP or file change; a broken file is refused and the
  previous grants stay.
- Logs are JSON and never contain passwords, signatures or tokens.

## Tests

```sh
just test          # unit tests (race detector)
just integration   # real registries and clients
just lint          # gofmt, vet, staticcheck, govulncheck
just fuzz          # the parsers that take untrusted input
```

The integration suite runs registry-pass against Distribution v3 in-process,
the official `registry:2.8.3` and `registry:3.0.0` images, and the unmodified
`docker` CLI using the credential helper, pushing and pulling real images.

What the tests try to break:

| Attack or failure | Where |
|---|---|
| Forged, tampered or re-signed login events; someone else's event; nsec or off-curve key as username | `internal/login`, fuzzed |
| Login for another realm (host suffix, http downgrade, user info, query, dot segments), method, kind or service | `internal/login` |
| Smuggled duplicate tags, stretched or backdated lifetimes, expired events, future timestamps | `internal/login` |
| Signature cache reused under another name, service or after expiry | `internal/login` |
| Scope smuggling (colons, traversal, `//`, case, encoded names, plugin classes) | `internal/grants`, fuzzed |
| Namespace prefix confusion (`alice-evil/`), namespace squatting via member names, deny-list precedence | `internal/grants`, integration |
| Weak or rotated static-user passwords, passwords over bcrypt's 72 bytes | `internal/grants` |
| Membership records not signed by an authority, impostor authority, content tampering | `internal/membership`, integration |
| Replay of an older `alive` record after a revocation, future-dated records, deletions by others | `internal/membership`, integration |
| Anonymous or failed-AUTH relay reads counted as fresh | `internal/membership` (embedded nmilat relay) |
| Rate-limit lockout of a victim's pubkey by forged requests, `X-Forwarded-For` / `-Proto` spoofing | `internal/server` |
| Secrets in logs, plain HTTP without TLS, oversized headers | `internal/server` |
| Forged JWTs at the registry: attacker key and cert, our cert with their signature, `alg: none`, HS256 keyed with our public key, tampered payload, foreign `aud`/`iss`, expired, embedded `jwk`, our `kid` with another key | integration, Distribution v3 |
| Tokens and `kid` formats checked by Distribution 2.8.3's and v3's own code | integration |
| Revocation mid-session, stale membership, static users unaffected | integration |
