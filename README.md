# registry-pass

Nostr logins for an OCI registry. Clients log in to a
[Distribution](https://github.com/distribution/distribution) registry with a
signed Nostr event instead of a password, and get a short-lived
token for the repositories they may use. Membership comes from events signed
by an authority key. The registry itself is unmodified.

Works with self-hosted registries that support external token auth, such as
Distribution. Hosted registries (GitHub, Docker Hub, ECR) run their own login
and can't use it.

## Setup

```sh
registry-pass keygen --key-out /run/secrets/pass.key --cert-out pass.crt
registry-pass --config config.yaml config check
registry-pass --config config.yaml serve
```

Start from [deploy/examples/](deploy/examples/). A Helm chart is in
[deploy/helm/](deploy/helm/registry-pass).

Point the registry at registry-pass:

```yaml
auth:
  token:
    realm: https://pass.example/token
    service: registry.example
    issuer: registry-pass
    rootcertbundle: /etc/registry/pass.crt
```

Use a DNS name for registry-pass, not an IP address: crane, kaniko and ko
refuse a token realm on a private IP.

## Clients

Add the credential helper to `~/.docker/config.json`:

```json
{ "credHelpers": { "registry.example": "registry-pass" } }
```

and configure it in `~/.config/registry-pass/helper.yaml`
([example](deploy/examples/helper.yaml)). It signs with a key file, an
environment variable, a NIP-46 bunker or a local socket signer.

## Configuration

Every setting has a default and can be overridden with a `REGISTRY_PASS_*`
environment variable. `registry-pass config env` lists them, and
`registry-pass config print` shows the effective values.

## Development

```sh
just test          # unit tests
just integration   # against real registries and the docker CLI
just lint
```
