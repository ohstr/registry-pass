---
name: registry-pass-grants
description: Write and check registry-pass's grants.yaml, which decides who may pull, push or delete which repositories. Use when giving members their own namespace, sharing a namespace with a team, adding a CI or agent key, a static pull account for Kubernetes nodes, public (anonymous) pulls, catalog access or a deny list, when a member is unexpectedly refused (reserved names, reserve false), or when reloading grants.
license: Unlicense
---

# registry-pass grants

`grants.yaml` (the file `grants.file` names) is the only place access is
decided. A token grants the intersection of what a client asks for and what
this file allows; anything else is left out of the token.

```yaml
templates:                     # every alive member
  - {repos: "{name}/**", actions: [pull, push]}
reservedNames: [admin, library]
anonymous: []                  # requests without credentials
identities:                    # by public key, member or not
  npub1...:
    - {repos: "team/**", actions: [pull, push]}
staticUsers:                   # Basic user + bcrypt password
  node-pull:
    bcrypt: "$2a$12$..."
    grants: [{repos: "**", actions: [pull]}]
catalog: []                    # keys allowed to list the catalog
deny: []                       # keys always refused
```

## Patterns

- Matched by path segment: `*` matches within one segment (`team-*`), `**`
  matches one or more whole segments. `alice/**` matches `alice/x` and
  `alice/x/y`, not `alice` and never `alice-evil/x`.
- `{name}` (templates only) is the member's name from their membership record.
- Actions: `pull`, `push`, `delete`, `*` (all three). Asking for `*` needs `*`.

## Reserved names

A member whose name is reserved gets no template grant. Names are reserved
when listed in `reservedNames`, and automatically (`grants.autoReserve`) when
a grant's first segment is a literal: `bodies/**` in `identities` reserves
`bodies`, so a newcomer named `bodies` can't take that shared namespace.

**Grants into a member's own namespace need `reserve: false`.** Otherwise the
member's name is reserved and they lose their namespace:

```yaml
identities:
  npub1...alice-ci:            # alice's CI key
    - {repos: "alice/**", actions: [pull, push], reserve: false}
```

`reservedNames` always wins over `reserve: false`.

## Rules the file is checked against

The whole file is refused (and the previous one stays in force) when:

- a key is not a valid npub, nprofile or hex public key (an nsec is refused),
  or the same key appears twice in any spelling;
- a template has no `{name}`, or `{name}` is used outside templates;
- a pattern has an empty, `..` or uppercase segment, a partial `**`, or more
  than two `**`;
- an action is unknown;
- a static user's hash is not bcrypt or has cost below 10, or the user name
  looks like a public key;
- a YAML key is unknown or repeated.

Check a file without starting the server:

```sh
REGISTRY_PASS_GRANTS__FILE=grants.yaml registry-pass --config config.yaml config check
```

## Reload

`grants.reload: sighup` (default) re-reads on `kill -HUP`; `watch` re-reads on
save (works with Kubernetes ConfigMaps); `none` needs a restart. A refused
file is logged and counted in
`registry_pass_grants_reloads_total{result="error"}`.

## Recipes

| Want | Grant |
|---|---|
| Members publish, everyone pulls | `templates: {name}/** pull,push` + `anonymous: ** pull` |
| A team namespace | `identities: <each key>: acme/** pull,push` |
| A CI or agent key for a member | `identities: <key>: alice/** pull,push, reserve: false` |
| Curated public catalog | curator `identities: verified/** pull,push,delete` + `anonymous: verified/** pull` |
| Kubernetes nodes pull everything | `staticUsers: node-pull: grants ** pull` |
| Block someone now | add the key to `deny` and reload |

Make a bcrypt hash: `htpasswd -nbBC 12 '' "$PASSWORD" | cut -d: -f2`.
