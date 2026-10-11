# Verified catalog

Members publish freely under their own name. A curator reviews agents and
copies the good ones to `verified/`, the only namespace open to the public.

```yaml
identities:
  npub1...curator:
    - {repos: "verified/**", actions: [pull, push, delete]}
    - {repos: "**", actions: [pull]}
anonymous:
  - {repos: "verified/**", actions: [pull]}
catalog: [npub1...curator]
```

The curator promotes a reviewed version, pinned by digest, with
[crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
(it uses the same credential helper):

```sh
crane copy registry.example/alice/summarizer@sha256:3f2a... \
           registry.example/verified/summarizer:1.0
```

The public runs only verified agents:

```sh
docker run registry.example/verified/summarizer:1.0
```

`verified` is reserved automatically because a grant names it, so no member
can be called `verified`.
