# syntax=docker/dockerfile:1

# Release images. Build one with --target control-plane or --target agent.

# The web UI is plain static files, so it builds once on the build machine's
# platform. Install scripts stay disabled.
FROM --platform=$BUILDPLATFORM node:26.13.0-alpine3.24@sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web ./
RUN npm run build

# The builders run on the build machine's platform and cross-compile for
# the target platform, so multi-platform builds need no emulation. Each image
# compiles only its own binary; the build cache mount lets a second image
# built on the same machine reuse the packages they share.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH

FROM builder AS build-control-plane
# the control plane embeds the UI build
COPY --from=web /src/internal/webui/dist/app ./internal/webui/dist/app
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath \
        -ldflags="-s -w -X github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version.Version=${VERSION}" \
        -o /out/server ./cmd/server

FROM builder AS build-agent
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath \
        -ldflags="-s -w -X github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version.Version=${VERSION}" \
        -o /out/agent ./cmd/agent

# static, CA certificates, no shell; runs as uid 65532
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS control-plane
COPY --from=build-control-plane /out/server /server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS agent
COPY --from=build-agent /out/agent /agent
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/agent"]
