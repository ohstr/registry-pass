# registry-pass

Nostr logins for an OCI registry. Clients log in to a
[Distribution](https://github.com/distribution/distribution) registry with a
signed Nostr event instead of a password, and get a short-lived
token for the repositories they may use. Membership comes from events signed
by an authority key. The registry itself is unmodified.

It fits a community that hosts its agents: each member publishes agent images
under their own name, with their Nostr key, and the community decides who is
a member.

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

## Examples

**Members share agents with everyone.** In `grants.yaml`:

```yaml
templates:
  - {repos: "{name}/**", actions: [pull, push]}
anonymous:
  - {repos: "**", actions: [pull]}
```

```sh
docker push registry.example/alice/summarizer:1.0   # alice, a member
docker run registry.example/alice/summarizer:1.0    # anyone
```

**Add or remove a member.** The authority publishes a signed record, here
with [ncli](https://github.com/ohstr/ncli); `status` is `alive` or `dead`:

```sh
cat > alice.json <<EOF
{"kind": 30078, "created_at": $(date +%s), "tags": [["d", "member:alice"]],
 "content": "{\"name\":\"alice\",\"pubkey\":\"npub1...\",\"status\":\"alive\"}"}
EOF
ncli publish -e alice.json -s wss://relay.example --signer bunker+unix:///run/authority.sock
```

**Publish from CI.** Give the pipeline its own key, limited to Alice's
namespace, and set `signer: env:NOSTR_NSEC` in the helper's config:

```yaml
identities:
  npub1...alice-ci:
    - {repos: "alice/**", actions: [pull, push], reserve: false}
```

More in [examples/](examples/): a verified catalog, team namespaces, runtime
nodes, and agents with their own key.

## Configuration

Every setting has a default and can be overridden with a `REGISTRY_PASS_*`
environment variable. `registry-pass config env` lists them, and
`registry-pass config print` shows the effective values.

## Agent skills

registry-pass ships skills for AI agents on operating it, writing grants,
managing membership and setting up clients:

```sh
registry-pass skills list
registry-pass skills install --dir <your agent's skills directory>
```

## Development

```sh
just test          # unit tests
just integration   # against real registries and the docker CLI
just lint
```
