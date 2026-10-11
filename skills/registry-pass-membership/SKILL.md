---
name: registry-pass-membership
description: Manage who is a member of a registry-pass registry by publishing membership records signed by the authority key - add a member, change their key, rename or remove them, and keep the heartbeat going. Use when onboarding or revoking members, choosing a membership source (relay, file, HTTP feed), setting up the relay reader key, or when a member is refused because the view is stale, their record is invalid, or two records claim the same key.
license: Unlicense
---

# registry-pass membership

Members are Nostr addressable events (kind `membership.kind`, default 30078)
signed by one of `membership.authorities`. Only signatures count: whoever
delivers the records can't forge or alter them.

## The record

```json
{"kind": 30078, "created_at": <now>, "tags": [["d", "member:alice"]],
 "content": "{\"name\":\"alice\",\"pubkey\":\"npub1...\",\"status\":\"alive\"}"}
```

- The name is the `d` tag after `dPrefix`; `content.name` must match it.
- `pubkey`: npub or hex; empty means no access yet.
- `status`: `alive` or `dead`.
- The newest record per name wins (highest `created_at`, then lowest id), so
  always set `created_at` to now. An older record never replaces a newer one,
  even if a source replays it. Records dated in the future are ignored.
- A record the authority signed but that can't be read (bad JSON, bad key,
  wrong name) counts as no access: a broken update locks out rather than
  leaving an old grant in place.

## Publishing with ncli

`ncli publish` signs a draft (no `id`/`sig`) with the authority key and sends
it. It does not set `created_at`, so the draft must:

```sh
record() { # name pubkey status
  cat > "member-$1.json" <<EOF
{"kind": 30078, "created_at": $(date +%s), "tags": [["d", "member:$1"]],
 "content": "{\"name\":\"$1\",\"pubkey\":\"$2\",\"status\":\"$3\"}"}
EOF
  ncli publish -e "member-$1.json" -s wss://relay.example \
    --signer bunker+unix:///run/authority/signer.sock
}

record alice npub1...alice alive      # add
record alice npub1...newkey alive     # new key; the old one stops working
record alice "" dead                  # remove
```

Rename: publish the new name `alive`, then the old name `dead`. While both
are alive the key is refused (`duplicatePubkey: denyAll`).

Changes apply at the member's next token request; tokens already issued
expire within `token.lifetime`. A NIP-09 deletion of the record by the same
authority also removes it (`honorDeletions`).

## Sources

- `relay`: subscribes for the authorities' records; with `reader` it
  authenticates (NIP-42) using a key file, `bunker://` or `bunker+unix://`.
- `file`: JSONL of signed events, re-read on change and every `pollInterval`.
- `http`: GET returning a JSON array of signed events, every `interval`.

Several sources are merged. A record missing from a source never removes
anyone: only `dead` (or a deletion) does.

## Freshness

The view is fresh while a source synced within `staleAfter` (for a relay with
a reader: synced and AUTH succeeded). With `heartbeat.enabled`, freshness
comes only from an authority-signed heartbeat (`d` = `heartbeat.d`), so a
relay that stops delivering new records can't keep a removed member in:

```sh
echo "{\"kind\":30078,\"created_at\":$(date +%s),\"tags\":[[\"d\",\"registry-pass:heartbeat\"]],\"content\":\"\"}" > hb.json
ncli publish -e hb.json -s wss://relay.example --signer bunker+unix:///run/authority/signer.sock
```

Publish it more often than `staleAfter`. When stale, `onStale` decides:
`denyMembers` (members get no template grants; identities, static users and
anonymous keep working), `denyAll` (Nostr logins get 503) or `keepLastView`.

## Checking

- `registry_pass_membership_members`, `_fresh`, `_heartbeat_age_seconds`,
  `_conflicts`, `_source_sync_age_seconds{source}`, `_relay_auth_ok{relay}`.
- `registry_pass_membership_events_rejected_total{reason}`: `not_authority`,
  `bad_signature`, `future_dated`, `older_than_current`, `deleted`,
  `other_d`, `wrong_kind`.
