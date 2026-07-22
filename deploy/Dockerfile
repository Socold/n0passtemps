# syntax=docker/dockerfile:1.7

# Pinned by minor so a patch release of the toolchain is picked up without a
# repository change. A release pipeline should pin the digest instead
# (golang:1.27-alpine@sha256:...) so the image cannot change under a fixed tag.
ARG GO_IMAGE=golang:1.27-alpine

FROM ${GO_IMAGE} AS builder

WORKDIR /src

# Dependencies change far less often than the sources, so resolving them in
# their own layer keeps the module download out of every code rebuild.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH

# CGO_ENABLED=0 is what makes the result a static binary the distroless static
# base can run: the SQLite driver is modernc.org/sqlite, which is pure Go, so no
# libc is needed. -trimpath and -s -w keep the artefact free of local build
# paths and debug sections.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/Socold/n0passtemps/internal/version.Version=${VERSION} \
        -X github.com/Socold/n0passtemps/internal/version.Commit=${REVISION} \
        -X github.com/Socold/n0passtemps/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/n0passtemps-server ./cmd/n0passtemps-server \
 && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/Socold/n0passtemps/internal/version.Version=${VERSION} \
        -X github.com/Socold/n0passtemps/internal/version.Commit=${REVISION} \
        -X github.com/Socold/n0passtemps/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/n0passtemps-wizard ./cmd/n0passtemps-wizard

# Created here rather than at runtime: the final image has no shell, and the
# data directory must exist and be owned by uid 65532 before the server starts
# under a read-only root filesystem.
RUN mkdir -p /data/lib /data/etc \
 && chown -R 65532:65532 /data


FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="n0passtemps" \
      org.opencontainers.image.description="On-premise passwordless authentication server (WebAuthn/FIDO2, TOTP, recovery codes)" \
      org.opencontainers.image.source="https://github.com/Socold/n0passtemps" \
      org.opencontainers.image.documentation="https://github.com/Socold/n0passtemps/tree/main/docs" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"

COPY --from=builder /out/n0passtemps-server /usr/local/bin/n0passtemps-server
# Shipped alongside the server so an operator can run "kek init" and the config
# generator with nothing but this image, no Go toolchain on the host.
COPY --from=builder /out/n0passtemps-wizard /usr/local/bin/n0passtemps-wizard

# Both trees are owned by uid 65532 so the server can write its database and
# read its keyring without any capability or root step.
COPY --from=builder --chown=65532:65532 /data/lib /var/lib/n0passtemps
COPY --from=builder --chown=65532:65532 /data/etc /etc/n0passtemps

# The keyring is deliberately outside /var/lib/n0passtemps: the server refuses a
# keyring that resolves inside a configured data directory, because a key stored
# on the same volume as the ciphertext it protects is no protection at all once
# that volume is copied. Mount it from a separate volume or secret, mode 0600.
ENV N0PASSTEMPS_DATABASE_DATA_DIR=/var/lib/n0passtemps \
    N0PASSTEMPS_KEK_PATH=/etc/n0passtemps/kek/keyring.json \
    N0PASSTEMPS_SERVER_ADDR=0.0.0.0:8080 \
    N0PASSTEMPS_SERVER_ALLOW_PLAINTEXT=true

# Only the database and its write-ahead log live here. Everything else the
# process touches is either read-only or a runtime tmpfs, so the root filesystem
# can be mounted read-only.
VOLUME ["/var/lib/n0passtemps"]

WORKDIR /var/lib/n0passtemps

EXPOSE 8080

USER 65532:65532

# No HEALTHCHECK is declared. This base image has no shell, no curl and no wget,
# so any in-container probe would either fail permanently or require adding a
# binary that widens the attack surface. Liveness is checked from outside
# against GET /v1/health: see the Kubernetes probes in deploy/kubernetes and the
# note in deploy/docker-compose.yml.

# The configuration path is a flag rather than an environment variable: the
# file is read before any override can name it. Every other setting can be
# overridden from the environment.
ENTRYPOINT ["/usr/local/bin/n0passtemps-server", "-config", "/etc/n0passtemps/config.toml"]
