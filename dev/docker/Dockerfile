# Local development image. Tilt builds the binary on the host (fast, with the
# Go build cache) and this image only wraps it, so a code change rebuilds in
# seconds. Release images come from the Dockerfile at the repository root.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
ARG BINARY
COPY ${BINARY} /app
USER 65532:65532
ENTRYPOINT ["/app"]
