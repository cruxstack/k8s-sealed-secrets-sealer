# syntax=docker/dockerfile:1

# Release images. Build one with --target control-plane or --target agent.

# The web UI is plain static files, so it builds once on the build machine's
# platform. Install scripts stay disabled.
FROM --platform=$BUILDPLATFORM node:26.12.1-alpine3.24@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web ./
RUN npm run build

# The builder runs on the build machine's platform and cross-compiles for
# the target platform, so multi-platform builds need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
# the control plane embeds the UI build
COPY --from=web /src/internal/webui/dist/app ./internal/webui/dist/app

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
