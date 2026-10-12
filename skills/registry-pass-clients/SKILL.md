---
name: registry-pass-clients
description: Log in to a registry-pass registry from docker, podman, crane, ORAS, kaniko, CI pipelines or Kubernetes, using the docker-credential-registry-pass helper that signs Nostr login events with a key file, an environment variable, a NIP-46 bunker or a local socket signer. Use when setting up a client or CI job to push or pull agent images, configuring helper.yaml, or debugging 401/403 errors on push or pull.
license: Unlicense
---

# Clients

Clients send their npub as the username and a signed Nostr login event as
the password. `docker-credential-registry-pass` makes the event on demand, so
no password is stored.

## Set up the helper

`~/.docker/config.json` (podman, crane, ORAS and kaniko read it too):

```json
{ "credHelpers": { "registry.example": "registry-pass" } }
```

`~/.config/registry-pass/helper.yaml`, or the file named by
`DOCKER_CREDENTIAL_REGISTRY_PASS_CONFIG`:

```yaml
registries:
  registry.example:
    realm: https://pass.example/token     # the registry's token realm
    service: registry.example
    signer: file:///home/me/.nostr/key.nsec
    lifetime: 1h          # <= the server's login.maxLifetime; min 5m
    refreshAt: 0.5        # sign anew when half the lifetime is left
    signerTimeout: 60s
```

Signers:

| `signer` | Key lives |
|---|---|
| `file:///path` | in a file holding an nsec or hex key; must be mode 0600 |
| `env:NAME` | in an environment variable (CI secrets) |
| `bunker://...` | in a NIP-46 remote signer; the session is kept for reuse |
| `bunker+unix:///path.sock` | in a local socket signer next to the client |

The helper caches the event in `$XDG_CACHE_HOME/registry-pass` (0600) and
refuses cache or key files others can read. `docker login` and `logout` are
not needed; they succeed and do nothing.

## Use it

```sh
docker push registry.example/alice/agent:1.0
docker pull registry.example/alice/agent:1.0
crane copy registry.example/alice/agent:1.0 registry.example/alice/agent:stable
oras push registry.example/alice/agent/results:1 report.md
```

## CI

Store an nsec as a secret and use `signer: env:NOSTR_NSEC`. Prefer a key of
its own for CI, granted only the namespaces it publishes to (with
`reserve: false` when that is a member's namespace).

## Kubernetes nodes

The kubelet can't run the helper: use a static pull user from `grants.yaml`
in a `docker-registry` secret and `imagePullSecrets`.

## Errors

| Symptom | Likely cause |
|---|---|
| `credentials not found in native keychain` | the registry host isn't in `helper.yaml` (match host:port exactly) |
| 401 on every request | wrong `realm`/`service`, clock skew, or `lifetime` above the server's `login.maxLifetime` |
| 401 `insufficient_scope` / `denied` on push | no grant for that repository; the token was issued without it |
| push works, then fails after hours | the key was removed from membership or grants |
| push `denied`, pull still works, other namespaces push | the namespace is at its storage quota: delete images (below) |
| `realm host ... is a private or link-local address` | crane/kaniko/ko refuse IP realms; use a DNS name |
| helper error about permissions | `chmod 600` the key file |

## Storage quota

When the registry caps each namespace, a full namespace gets no push but
keeps pull and delete. Docker only says `denied`. Check usage with the same
login the helper makes:

```sh
curl -s -u "$(echo registry.example | docker-credential-registry-pass get | jq -r '.Username + ":" + .Secret')" \
  https://pass.example/usage/alice
# {"used":10956718080,"quota":10737418240,"blobs":812}
```

Free space by deleting manifests (the template must grant `delete`), e.g.
`crane delete registry.example/alice/agent@sha256:...` or `regctl tag rm`.
Push comes back at the next token. The disk is reclaimed when the operator's
garbage collection runs. For more space, ask an authority to raise the
namespace's quota.
