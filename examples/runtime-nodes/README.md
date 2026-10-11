# Runtime nodes

Hosts and clusters that run agents need to pull, never push.

A host with a Nostr key gets a pull-only grant and uses the credential helper
like anyone else:

```yaml
identities:
  npub1...runtime:
    - {repos: "**", actions: [pull]}
```

Kubernetes nodes can't run a credential helper, so they use a static pull
account. Make the hash with `htpasswd -nbBC 12 '' "$PASSWORD" | cut -d: -f2`:

```yaml
staticUsers:
  node-pull:
    bcrypt: "$2a$12$..."
    grants: [{repos: "**", actions: [pull]}]
```

```sh
kubectl create secret docker-registry agents-pull \
  --docker-server=registry.example --docker-username=node-pull --docker-password="$PASSWORD"
```

```yaml
# in the agent's pod spec
imagePullSecrets: [{name: agents-pull}]
```

Static users keep working while the membership view is stale, so a relay
outage doesn't stop agents from starting.
