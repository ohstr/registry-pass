# Storage quota

Each member's namespace may hold 10GiB. When it is full, the member's new
passes carry pull and delete but no push, so one member, or an agent
pushing for them, can't fill the disk and block everyone else.

[config.yaml](config.yaml) turns the quota on, [registry.yaml](registry.yaml)
sends the registry's notifications to registry-pass, and
[grants.yaml](grants.yaml) gives members `delete` so they can clean up.

```sh
openssl rand -hex 32 > /run/secrets/events.token   # the same token goes in registry.yaml
registry-pass --config config.yaml config check
registry-pass --config config.yaml quota rebuild    # optional: count what's already there
```

Alice fills her namespace:

```sh
docker push registry.example/alice/summarizer:2.0
# denied: requested access to the resource is denied
```

registry-pass logs why, and returns it in the token response's `warnings`:

```
namespace alice: 10.2GiB of 10GiB used — push refused; delete images to free space
```

She checks her usage and deletes an old image. Push works again at her next
pass, before any garbage collection:

```sh
curl -s -u "$(echo registry.example | docker-credential-registry-pass get | jq -r '.Username + ":" + .Secret')" \
  https://pass.example/usage/alice
# {"used":10956718080,"quota":10737418240,"blobs":812}
crane delete registry.example/alice/summarizer@sha256:...
docker push registry.example/alice/summarizer:2.0
```

The operator reclaims the disk on a schedule:

```sh
registry garbage-collect --delete-untagged /etc/docker/registry/config.yml
```

## More space for one member

An authority key raises Alice's quota without a config change. It applies
at her next pass:

```sh
cat > quota-alice.json <<EOF
{"kind": 30078, "created_at": $(date +%s), "tags": [["d", "quota:alice"]],
 "content": "{\"name\":\"alice\",\"quota\":\"50GiB\"}"}
EOF
ncli publish -e quota-alice.json -s wss://relay.example --signer bunker+unix:///run/authority.sock
```

A record signed by any other key is ignored. Editing `perName` in the
config and reloading (SIGHUP) works too.

## Watching it

```promql
registry_pass_quota_used_bytes / registry_pass_quota_bytes > 0.9
```
