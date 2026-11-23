# syntax=docker/dockerfile:1

# Release images. Build one with --target control-plane or --target agent.

# The web UI is plain static files, so it builds once on the build machine's
# platform. Install scripts stay disabled.
FROM --platform=$BUILDPLATFORM node:26.13.1-alpine3.24@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web ./
RUN npm run build

# The builders run on the build machine's platform and cross-compile for
# the target platform, so multi-platform builds need no emulation. Each image
# compiles only its own binary; the build cache mount lets a second image
# built on the same machine reuse the packages they share.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

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
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS control-plane
COPY --from=build-control-plane /out/server /server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS agent
COPY --from=build-agent /out/agent /agent
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/agent"]
