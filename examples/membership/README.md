# Adding and removing members

Membership is a record the authority signs and publishes to the relay
registry-pass reads. These commands use [ncli](https://github.com/ohstr/ncli)
with the authority key behind a socket signer.

`record` writes one membership record. `created_at` must be now: the newest
record for a name wins, so an old date would be ignored.

```sh
record() { # name pubkey status
  cat > "member-$1.json" <<EOF
{"kind": 30078, "created_at": $(date +%s), "tags": [["d", "member:$1"]],
 "content": "{\"name\":\"$1\",\"pubkey\":\"$2\",\"status\":\"$3\"}"}
EOF
  ncli publish -e "member-$1.json" -s wss://relay.example \
    --signer bunker+unix:///run/authority/signer.sock
}
```

Add Alice; she can push to `alice/` at once:

```sh
record alice npub1...alice alive
```

Alice lost her key and has a new one; the old key stops working:

```sh
record alice npub1...alicenew alive
```

Remove her; from her next request on, she can't push or pull private repos:

```sh
record alice "" dead
```

Tokens already issued expire within `token.lifetime` (5 minutes by default).

## Heartbeat

With `membership.heartbeat.enabled: true`, registry-pass only trusts the view
while the authority keeps publishing a heartbeat, so a relay that stops
delivering new records can't keep a removed member in. Publish one more often
than `membership.staleAfter` (30 minutes by default), for example from cron:

```sh
*/10 * * * * echo "{\"kind\":30078,\"created_at\":$(date +\%s),\"tags\":[[\"d\",\"registry-pass:heartbeat\"]],\"content\":\"\"}" > /tmp/hb.json && ncli publish -e /tmp/hb.json -s wss://relay.example --signer bunker+unix:///run/authority/signer.sock
```
