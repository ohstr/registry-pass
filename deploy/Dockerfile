# Build from the repository root:
#   docker build -f deploy/Dockerfile -t registry-pass .
FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY skills ./skills
ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/registry-pass ./cmd/registry-pass \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/docker-credential-registry-pass ./cmd/docker-credential-registry-pass

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/registry-pass /usr/local/bin/registry-pass
COPY --from=build /out/docker-credential-registry-pass /usr/local/bin/docker-credential-registry-pass
USER nonroot:nonroot
EXPOSE 5001
ENTRYPOINT ["/usr/local/bin/registry-pass"]
CMD ["serve"]
