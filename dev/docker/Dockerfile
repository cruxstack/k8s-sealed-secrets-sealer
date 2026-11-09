# Local development image. Tilt builds the binary on the host (fast, with the
# Go build cache) and this image only wraps it, so a code change rebuilds in
# seconds. Release images come from the Dockerfile at the repository root.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
ARG BINARY
COPY ${BINARY} /app
USER 65532:65532
ENTRYPOINT ["/app"]
