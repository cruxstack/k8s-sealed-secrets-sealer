# syntax=docker/dockerfile:1

# Release images. Build one with --target control-plane or --target agent.

# The builder runs on the build machine's platform and cross-compiles for
# the target platform, so multi-platform builds need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go build -trimpath \
        -ldflags="-s -w -X github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version.Version=${VERSION}" \
        -o /out/server ./cmd/server \
    && go build -trimpath \
        -ldflags="-s -w -X github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version.Version=${VERSION}" \
        -o /out/agent ./cmd/agent

# static, CA certificates, no shell; runs as uid 65532
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS control-plane
COPY --from=builder /out/server /server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS agent
COPY --from=builder /out/agent /agent
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/agent"]
