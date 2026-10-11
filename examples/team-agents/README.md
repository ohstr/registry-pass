# Team agents

A team keeps its agents in `acme/`, private to its members' keys. Without an
`anonymous` grant, nobody else can pull them.

```yaml
identities:
  npub1...lead:
    - {repos: "acme/**", actions: [pull, push, delete]}
  npub1...dev:
    - {repos: "acme/**", actions: [pull, push]}
```

Either of them:

```sh
docker push registry.example/acme/triage-agent:2.3
```

Adding someone to the team is one entry in `grants.yaml`; registry-pass picks
it up on reload (SIGHUP, or on save with `grants.reload: watch`). `acme` is
reserved automatically, so no member can register that name.
