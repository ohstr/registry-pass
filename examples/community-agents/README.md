# Community agents

Every member gets a namespace named after them and publishes agents there.
Anyone can pull, without logging in.

```yaml
templates:
  - {repos: "{name}/**", actions: [pull, push]}
anonymous:
  - {repos: "**", actions: [pull]}
reservedNames: [library, verified, admin]
```

Alice, a member named `alice`, publishes her summarizer:

```sh
docker build -t registry.example/alice/summarizer:1.0 .
docker push registry.example/alice/summarizer:1.0
```

Anyone runs it:

```sh
docker run registry.example/alice/summarizer:1.0
```

Alice can't push to `bob/` or to a look-alike such as `alice-tools/`, and no
member can claim the names in `reservedNames`.
