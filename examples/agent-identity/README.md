# An agent with its own identity

Give a running agent its own Nostr key and a narrow grant. It can pull its own
image and publish what it produces, and nothing else.

```yaml
identities:
  npub1...summarizer:
    - {repos: "alice/summarizer/results/**", actions: [pull, push], reserve: false}
    - {repos: "alice/summarizer", actions: [pull], reserve: false}
```

`reserve: false` keeps `alice/` Alice's: grants into a member's own namespace
must not reserve the name.

Keep the key out of the agent: run a socket signer next to it and point the
helper at the socket.

```yaml
# helper.yaml inside the agent's container
registries:
  registry.example:
    realm: https://pass.example/token
    service: registry.example
    signer: bunker+unix:///run/signer/agent.sock
```

The agent pushes a report as an OCI artifact with
[ORAS](https://oras.land), which uses the same credential helper:

```sh
oras push registry.example/alice/summarizer/results/2026-10-11:latest report.md
```

If the agent misbehaves, remove its entry from `grants.yaml`, or add its key to
`deny`, and it loses access at its next request.
