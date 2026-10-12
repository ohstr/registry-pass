# Storage quota

A cap on what each top-level namespace stores, enforced where push rights
are decided: in the passes.

## 1. registry-pass

```yaml
quota:
  enabled: true
  default: 10GiB
  perName: {alice: 50GiB}
  exempt: [verified, npub1...ci]
  registry: http://registry:5000
  eventsTokenFile: /run/secrets/events.token
  store: /var/lib/registry-pass/quota.db
```

- `registry` is the registry's API as registry-pass reaches it, often an
  internal address. registry-pass signs its own read-only tokens for it
  (catalog and pull, audience `quota.service`, default the first of
  `services`), so it needs no other credentials.
- `store` is a bbolt file. Put it on a volume: without it, every start
  recounts the whole registry. Only one process may open it, so run one
  replica with the module on.
- `eventsTokenFile` holds a random token, e.g. `openssl rand -hex 32`.
- Sizes: bytes, `KB`/`MB`/`GB`/`TB` (1000) or `KiB`/`MiB`/`GiB`/`TiB` (1024).
- `exempt`: namespace names, or keys whose pushes are never capped (a
  curator, a mirror job).

## 2. Distribution

Send notifications to registry-pass:

```yaml
notifications:
  endpoints:
    - name: registry-pass
      url: http://registry-pass:5001/events
      headers:
        Authorization: [Bearer <the events token>]
      timeout: 5s
      threshold: 5
      backoff: 1s
```

registry-pass answers at once and recounts in the background. If it is down,
the registry retries. Run `registry-pass quota rebuild` after a long outage,
or leave it to `rebuildInterval` (default 24h).

## 3. Garbage collection

Usage counts what tags reach. Deleting a manifest or a tag lowers it at
once, but the disk keeps the blobs until garbage collection:

```sh
registry garbage-collect --delete-untagged /etc/docker/registry/config.yml
```

Schedule it (e.g. nightly, with the registry read-only or stopped, as
Distribution requires). Without `--delete-untagged`, an overwritten tag
leaves its old image on disk, uncounted.

## What counts

- Per namespace, the distinct blobs reached from every tag of every
  repository under it: manifests (and an index's child manifests), configs
  and layers, at their stored size. A blob shared by two repositories of a
  namespace counts once; a blob used by two namespaces counts in each.
- Not counted: untagged manifests (pushed by digest only), orphan uploads,
  and foreign layers the registry doesn't store. GC removes the first two.

## Raising one namespace without editing the config

An authority (`membership.authorities`) publishes, through the membership
sources:

```json
{"kind": 30078, "created_at": <now>, "tags": [["d", "quota:alice"]],
 "content": "{\"name\":\"alice\",\"quota\":\"50GiB\"}"}
```

The newest record for a name wins and overrides `perName` and `default`;
it applies at the next pass. Records from other keys are ignored. A NIP-09
deletion, or an unreadable record, falls back to the config. Needs
membership enabled.

## Rebuild

```sh
registry-pass --config config.yaml quota rebuild
```

With no server running, it opens the store and recounts. When a server
holds the store, it asks that server (`POST /quota/rebuild` on
`server.listen`, authenticated with the events token; `--url` to override).
It prints each namespace's usage.

## Usage and metrics

- `GET /usage/<name>` → `{"used": 10956718080, "quota": 10737418240, "blobs": 812}`
  for the namespace's owner (a member logged in as for `/token`) or a key in
  the grants' `catalog` list. `503` until the first recount ends.
- `registry_pass_quota_used_bytes{name}`, `registry_pass_quota_bytes{name}`
  (absent for exempt names), `registry_pass_quota_ready`,
  `registry_pass_quota_push_refused_total`,
  `registry_pass_quota_recounts_queued_total`,
  `registry_pass_quota_recount_errors_total`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Push `denied`, pull works | Namespace full: see the `warnings` in the token response or the log line, delete images |
| Usage doesn't drop after a delete | The registry isn't sending notifications (check its logs for `/events`), or the token differs (401 in registry-pass's logs) |
| `/usage` answers 503 | The first recount hasn't finished: check `registry_pass_quota_ready` and the logs for `rebuild failed` |
| Usage drops but the disk doesn't | GC hasn't run, or runs without `--delete-untagged` |
| Startup fails with `quota store … in use` | Another process (a second replica, or `quota rebuild`) holds the store |
