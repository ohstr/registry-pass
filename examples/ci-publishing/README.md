# Publishing from CI

Give CI its own key instead of a member's: it can push only where its grant
says, and removing it from `grants.yaml` revokes it without touching the
member.

```yaml
identities:
  npub1...cibot:                # alice's CI key
    - {repos: "alice/**", actions: [pull, push], reserve: false}
```

`reserve: false` says `alice/` is Alice's own namespace. Without it, the name
`alice` would be reserved like a shared namespace and Alice would lose access
to it.

Store the CI key's nsec as a repository secret named `NOSTR_NSEC`, then:

```yaml
# .github/workflows/publish.yml
on:
  push:
    tags: ["v*"]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install the credential helper
        run: |
          curl -sL https://github.com/ohstr/registry-pass/releases/latest/download/registry-pass_linux_amd64.tar.gz \
            | sudo tar -xz -C /usr/local/bin docker-credential-registry-pass
          mkdir -p ~/.config/registry-pass ~/.docker
          cat > ~/.config/registry-pass/helper.yaml <<EOF
          registries:
            registry.example:
              realm: https://pass.example/token
              service: registry.example
              signer: env:NOSTR_NSEC
          EOF
          echo '{"credHelpers":{"registry.example":"registry-pass"}}' > ~/.docker/config.json
      - name: Build and push
        env:
          NOSTR_NSEC: ${{ secrets.NOSTR_NSEC }}
        run: |
          docker build -t registry.example/alice/summarizer:${GITHUB_REF_NAME} .
          docker push registry.example/alice/summarizer:${GITHUB_REF_NAME}
```

Each login event the helper signs is valid for an hour at most, so a leaked
one is useless soon after.
