# registry-pass configuration reference

Every key with its default. Run `registry-pass config print` for the values
in effect and `registry-pass config env` for the override names.

```yaml
realm: ""                     # (required) public URL of /token
services: []                  # (required) accepted `service` values
issuer: registry-pass         # JWT iss; must equal the registry's auth.token.issuer

server:
  listen: ":5001"
  tls: {certFile: "", keyFile: "", minVersion: "1.2"}   # 1.2 | 1.3; empty = TLS ends at a proxy
  requireTLS: true            # refuse plain HTTP unless a trusted proxy says X-Forwarded-Proto: https
  trustedProxies: []          # CIDRs or IPs whose X-Forwarded-For/-Proto are believed
  tokenPath: /token
  postToken: notFound         # notFound | methodNotAllowed
  readTimeout: 10s
  writeTimeout: 10s
  idleTimeout: 1m
  maxHeaderBytes: 16384       # min 4096: the Basic password carries a whole event
  shutdownGrace: 15s

admin:
  listen: ""                  # "" = same listener; must differ from server.listen
  healthPath: /healthz
  readyPath: /readyz
  metricsPath: /metrics
  metrics: true

login:
  kind: 27235
  maxLifetime: 1h             # max expiration - created_at of a login event
  minRemaining: 2m            # refuse events expiring sooner (>= token.minLifetime)
  clockSkew: 30s              # tolerated future created_at
  requireServiceTag: false
  usernameFormats: [npub, nprofile, hex]
  cacheSize: 10000            # verified events kept until expiry; 0 = off

token:
  signingKeyFile: ""          # (required) PEM key; EC P-256/P-384 or RSA >= 2048
  certificateFile: ""         # (required) the cert the registry trusts
  chainFile: ""
  algorithm: ES256            # ES256 | ES384 | RS256 (must fit the key)
  lifetime: 5m
  minLifetime: 1m             # min 60s
  capToLoginExpiry: true      # token never outlives the login event
  x5c: true                   # both Distribution 2.8 and v3 verify x5c
  kid: auto                   # auto | libtrust (2.8 without x5c) | thumbprint (v3 without x5c) | none
  certExpiryWarning: 720h

membership:
  enabled: true               # false = static users, identities and anonymous only
  authorities: []             # npub or hex; required when enabled
  kind: 30078                 # addressable kind of membership records
  dPrefix: "member:"
  pubkeyField: pubkey         # content field with the member's npub or hex (e.g. npub)
  nameMismatch: reject        # reject | useD (content.name differs from the d tag)
  resolve: latest             # latest | deadWins (records from several authorities)
  futureSkew: 30s
  honorDeletions: true        # NIP-09 deletions by an authority revoke
  duplicatePubkey: denyAll    # denyAll | newestWins (two alive records, one key)
  emptyPubkey: noAccess
  staleAfter: 30m             # view is stale after this long without a sync
  onStale: denyMembers        # denyMembers | denyAll | keepLastView
  heartbeat: {enabled: false, d: "registry-pass:heartbeat"}
  sources:                    # one or more, combined; file-only (no env)
    - relay:
        urls: [wss://relay.example]
        reader: {keyFile: "", signer: "", signerTimeout: 30s}   # one of keyFile / signer (bunker:// or bunker+unix://)
        requireAuth: true     # with a reader: fresh only when AUTH succeeded
        authWait: 5s
        resync: 10m           # < staleAfter
        pageSize: 500
        dedupeSize: 50000
    - file:
        path: /etc/registry-pass/members.jsonl   # JSONL of signed events
        watch: true
        pollInterval: 30s     # < staleAfter
    - http:
        url: https://feed.example/members        # JSON array of signed events
        interval: 1m          # < staleAfter
        timeout: 10s
        headers: {}           # e.g. {Authorization: "Bearer {file:/run/secrets/feed.token}"}
        caFile: ""

grants:
  file: /etc/registry-pass/grants.yaml
  reload: sighup              # none | sighup | watch
  namePattern: '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'   # member names; anchored
  autoReserve: true           # reserve first segments named by grants (see reserve: false)
  staticUserCacheTTL: 1m      # bcrypt success cache; 0 = off

rateLimit:
  enabled: true
  perIP: 300/min              # before verification
  perPubkey: 120/min          # only after the signature verifies
  perStaticUser: 600/min
  failuresPerIP: 30/min
  burst: 20

quota:
  enabled: false              # off = no /events, /usage or quota checks (v0.2.0 behaviour)
  default: 10GiB              # each top-level namespace
  perName: {}                 # name → size, overrides default; file-only (no env)
  exempt: []                  # namespace names or pubkeys never capped
  registry: ""                # (required when enabled) registry API URL registry-pass walks, e.g. http://registry:5000
  registryCAFile: ""
  service: ""                 # audience of registry-pass's own tokens; "" = first of services
  store: /var/lib/registry-pass/quota.db   # bbolt file on a volume; rebuilt when missing
  eventsTokenFile: ""         # (required when enabled) bearer token the registry's notifications send
  dPrefix: "quota:"           # d tag of authority-signed quota records
  rebuildInterval: 24h        # full recount; 0 = only on start (store missing) and `quota rebuild`
  timeout: 30s                # each registry API call

logging:
  level: info                 # debug | info | warn | error
  format: json                # json | text
  logGranted: true            # false = log denials only
```
