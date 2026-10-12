---
name: registry-pass-operate
description: Deploy and run registry-pass, the token service that lets OCI registry clients log in with a signed Nostr event. Use when installing it, writing or validating its config (config check/print/env, REGISTRY_PASS_* overrides), generating the signing key (keygen), wiring a Distribution registry to it (auth.token, rootcertbundle, notifications), setting storage quotas per namespace (quota rebuild, /usage), putting it behind TLS or a proxy, reading its metrics and logs, or finding out why a token request was refused or a push was not granted.
license: Unlicense
---

# Operating registry-pass

registry-pass answers the registry's token flow: the registry sends clients
to `realm`, they log in with their npub and a signed Nostr event, and get a
short-lived JWT the registry verifies with registry-pass's certificate.

## Install

```sh
registry-pass keygen --key-out /run/secrets/pass.key --cert-out pass.crt
registry-pass --config config.yaml config check   # validates config and every file it names
registry-pass --config config.yaml serve
```

`keygen` refuses to overwrite files without `--force`; the key is written 0600.
The image is `ghcr.io/ohstr/registry-pass` (distroless, non-root); the Helm
chart is in `deploy/helm/registry-pass`.

## Wire the registry

Distribution's `config.yml`; `service` and `issuer` must match registry-pass's
`services` and `issuer`, and `realm` its public `/token` URL:

```yaml
auth:
  token:
    realm: https://pass.example/token
    service: registry.example
    issuer: registry-pass
    rootcertbundle: /etc/registry/pass.crt
```

Give registry-pass a DNS name: crane, kaniko and ko refuse token realms on
private IP literals.

## Configure

- One YAML file (`--config`, or `$REGISTRY_PASS_CONFIG`), every key optional
  except `realm`, `services`, `token.signingKeyFile`, `token.certificateFile`
  and, with membership on, `membership.authorities` and one source.
- Environment overrides: `REGISTRY_PASS_` + key path in UPPER_SNAKE, levels
  joined by `__` (`REGISTRY_PASS_LOGIN__MAX_LIFETIME=2h`). Lists are
  comma-separated. Sources are file-only. An unknown `REGISTRY_PASS_*`
  variable is an error.
- Secrets only from files (`*File` keys, `{file:/path}` in HTTP headers).
- `config print` shows every value and whether it came from default, file or
  env. `config env` lists every override name.
- Startup refuses invalid or inconsistent values; `config check` shows all of
  them at once.

Full key list with defaults: `references/config.md`.

### Settings people usually change

| Need | Setting |
|---|---|
| TLS ends at an ingress | `server.trustedProxies: [CIDR]` (else `requireTLS` refuses plain HTTP) |
| Serve TLS directly | `server.tls.certFile`, `server.tls.keyFile` |
| Health and metrics off the public port | `admin.listen: ":9090"` |
| Longer pushes | `login.maxLifetime` (default 1h; the helper's `lifetime` must not exceed it) |
| Shorter tokens | `token.lifetime` (min 60s) |
| What to do when membership can't sync | `membership.onStale`: `denyMembers` (default), `denyAll`, `keepLastView` |
| Rate limits | `rateLimit.perIP`, `perPubkey`, `perStaticUser`, `failuresPerIP` (`N/s`, `N/min`, `N/h`) |
| Grants reload | `grants.reload`: `sighup` (default), `watch`, `none` |
| Cap each namespace's storage | `quota.enabled: true`, `quota.default`, `quota.perName` (see below) |

## Endpoints

- `GET /token` (the realm). `POST /token` answers 404 so clients use GET.
- `/healthz` (process up), `/readyz` (process ready; never depends on
  membership, so static users keep working), `/metrics` (Prometheus).
- With the quota module on: `POST /events` (the registry's notifications),
  `GET /usage/<name>`, `POST /quota/rebuild`.

## Storage quota

Off by default. When on, a pass never grants `push` on a namespace (the
first path segment, `alice` in `alice/agent`) that is at or over its quota.
It still grants pull and delete, so the owner can clean up.

```yaml
quota:
  enabled: true
  default: 10GiB
  perName: {alice: 50GiB}            # overrides default
  exempt: [verified, npub1...ci]     # names or keys never capped
  registry: http://registry:5000     # registry API registry-pass reads
  eventsTokenFile: /run/secrets/events.token
  store: /var/lib/registry-pass/quota.db   # on a volume
```

Point the registry's notifications at `/events` with the same token, and
give it `timeout: 5s` or more. Setup, sizing and the GC schedule:
`references/quota.md`.

- Usage per namespace is the size of the distinct blobs its tags reach
  (manifests, configs, layers). A blob counts once per namespace, and in
  every namespace that uses it.
- Each push or delete notification makes registry-pass recount that
  repository through the registry API. `registry-pass quota rebuild`
  recounts everything (also on start when the store is missing, and every
  `rebuildInterval`); the recount is the source of truth. Until the first
  recount ends, pushes are not capped.
- A push in flight may overshoot by its own size; the next pass is refused.
  Deleting manifests lowers usage at once; disk comes back when the
  registry's garbage collection runs (`--delete-untagged`).
- Authority-signed records (`d` = `quota:<name>`) set one namespace's quota
  without editing the config (registry-pass-membership skill). Config
  changes to `default`, `perName` and `exempt` apply on reload (SIGHUP, or
  the watcher with `grants.reload: watch`).

A refused push shows in the token response's `warnings` and in a log line:
`namespace alice: 10.2GiB of 10GiB used — push refused; delete images to
free space`. Docker reports it only as `denied`.

`GET /usage/<name>` returns `{"used":…,"quota":…,"blobs":…}` to the
namespace's owner or a `catalog` (read-all) key, logged in as for `/token`.

## Why a request was refused

Every request is logged (JSON) with `subject`, `kind`, `service`, `result`,
`reason`, `requested` and `granted` scopes. Passwords, signatures and tokens
are never logged.

| Status | `reason` |
|---|---|
| 400 | `unknown_service` (the `service` param isn't in `services`), `too_many_scopes` |
| 401 | login refused, see below; `no_credentials`, `bad_password`, `account_mismatch`, `bad_authorization_header`, `login_expiring` |
| 403 | `denied` (deny list), `tls_required` |
| 429 | `rate_limited_ip`, `rate_limited_failures`, `rate_limited_pubkey`, `rate_limited_static_user` |
| 503 | `membership_stale` (only with `onStale: denyAll`) |

Login reasons: `bad_username` (not an npub/nprofile/hex key, or an nsec),
`malformed`, `too_large`, `wrong_kind`, `pubkey_mismatch`, `bad_tags`,
`wrong_realm` (the event's `u` tag isn't this realm), `wrong_method`,
`wrong_service`, `created_in_future` (client clock ahead), `expired`,
`lifetime_too_long` (over `login.maxLifetime`), `bad_signature`,
`content_not_empty`.

A 200 whose token grants nothing (`granted: []`) means the identity has no
grant for that repository: see the registry-pass-grants skill, or check
membership (registry-pass-membership).

## Metrics worth alerting on

- `registry_pass_membership_fresh == 0`: members are being denied.
- `registry_pass_certificate_expiry_seconds < 7d`: rotate the signing cert.
- `registry_pass_membership_relay_auth_ok == 0`: the reader key isn't
  accepted by the relay.
- `registry_pass_grants_reloads_total{result="error"}` increasing: a broken
  grants file was refused and the old one is still in force.
- `registry_pass_logins_total{result="denied"}` by `reason`.
- `registry_pass_quota_used_bytes{name} / registry_pass_quota_bytes{name} > 0.9`:
  a namespace is nearly full. `registry_pass_quota_ready == 0` for long, or
  `registry_pass_quota_recount_errors_total` increasing: registry-pass can't
  read the registry API, and usage is stale.

## Rotating the signing certificate

1. `registry-pass keygen` a new key and cert.
2. Append the new cert to the registry's `rootcertbundle` and restart the
   registry.
3. Switch registry-pass to the new key and cert.
4. After `token.lifetime`, remove the old cert from the bundle.
