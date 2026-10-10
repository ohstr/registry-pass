# GOWORK=off: the repo may sit under a directory with its own go.work.
export GOWORK := "off"

# Unit tests with the race detector.
test:
    go test -race -count=1 ./...

# Integration tests: in-process Distribution v3, plus the registry:2.8.3 and
# registry:3.0.0 images and the docker CLI when docker is available
# (RP_SKIP_DOCKER=1 to skip those).
integration:
    cd test/integration && go test -race -count=1 ./...

# Static analysis and vulnerability scan.
lint:
    test -z "$(gofmt -l .)"
    go vet ./...
    cd test/integration && go vet ./...
    go run honnef.co/go/tools/cmd/staticcheck@latest ./...
    go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Fuzz the parsers that take untrusted input.
fuzz time="60s":
    go test -run '^$' -fuzz '^FuzzVerify$' -fuzztime {{time}} ./internal/login
    go test -run '^$' -fuzz '^FuzzParseScope$' -fuzztime {{time}} ./internal/grants
    go test -run '^$' -fuzz '^FuzzTemplateIsolation$' -fuzztime {{time}} ./internal/grants

# Coverage summary of the unit tests.
cover:
    go test -count=1 -coverprofile=coverage.out ./...
    go tool cover -func=coverage.out | tail -1

build:
    go build -o bin/ ./cmd/...

image tag="registry-pass:dev":
    docker build -f deploy/Dockerfile -t {{tag}} .
