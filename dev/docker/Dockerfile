# Local development image. Tilt builds the binary on the host (fast, with the
# Go build cache) and this image only wraps it, so a code change rebuilds in
# seconds. Release images come from the Dockerfile at the repository root.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
ARG BINARY
COPY ${BINARY} /app
USER 65532:65532
ENTRYPOINT ["/app"]
