# syntax=docker/dockerfile:1
#
# Builds app-tail as a single static binary in a minimal runtime image. The
# dashboard is compiled and embedded, and the binary runs headless with no tray.
#
#   docker build -t app-tail .
#   docker compose up -d          # see docker-compose.yml for the host-network note

# Base images are pinned by digest, so a rebuild months from now produces the same
# image rather than whatever the tag has since been moved to. Refresh a digest with:
#   docker buildx imagetools inspect <image>:<tag>
#
# --- Stage 1: build the dashboard -------------------------------------------
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# --- Stage 2: build the static binary ---------------------------------------
# The patch level is spelled out so the tag and the digest name the same toolchain: go.mod
# asks for this exact version and the image builds with GOTOOLCHAIN=local, so a digest
# behind a floating minor tag fails `go mod download` as soon as go.mod moves ahead of it.
FROM golang:1.26.7-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The Go build embeds ui/dist via go:embed, so the freshly built dashboard has to
# be in place before the compile.
COPY --from=ui /ui/dist ./ui/dist
# The build identity comes from the host's scripts/version.sh, since .dockerignore
# keeps .git out of the context and the container cannot resolve it itself.
ARG APPTAIL_VERSION=dev
ARG APPTAIL_COMMIT=dev
ARG APPTAIL_DATE=dev
# notray drops the systray front end, which has no desktop session to attach to here.
# CGO_ENABLED=0 yields a portable static binary for the thin runtime below, and
# -trimpath keeps build paths out so the same commit produces the same binary.
RUN CGO_ENABLED=0 go build -trimpath -tags notray -o /out/app-tail \
	-ldflags="-s -w \
	-X github.com/sellitus/app-tail/internal/buildinfo.version=${APPTAIL_VERSION} \
	-X github.com/sellitus/app-tail/internal/buildinfo.commit=${APPTAIL_COMMIT} \
	-X github.com/sellitus/app-tail/internal/buildinfo.date=${APPTAIL_DATE}" .

# --- Stage 3: runtime --------------------------------------------------------
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
# ca-certificates lets the node reach the Tailscale control plane over TLS.
RUN apk add --no-cache ca-certificates \
	&& adduser -D -H -u 10001 apptail \
	&& mkdir -p /data && chown apptail:apptail /data
COPY --from=build /out/app-tail /usr/local/bin/app-tail
USER apptail
# /data holds the tailnet identity and config; keep it on a volume so a container
# replacement keeps the same device rather than enrolling a new one each time.
ENV APPTAIL_STATE_DIR=/data \
	APPTAIL_UI_ADDR=127.0.0.1:8377 \
	APPTAIL_HEADLESS=1
VOLUME ["/data"]
# The dashboard API is loopback-only by design and answers only callers holding the
# token in /data/api-token, so it is deliberately never EXPOSEd. Drive the node from inside the container with
# `docker exec <c> app-tail login|status|list|add|restart`.
# `health` asks /healthz, which is 503 unless the node is Running AND every enabled
# forward is listening. `status` exits 0 the moment the loopback API answers, so it
# reported healthy while the node sat in NeedsLogin and nothing was forwarded. The URL
# is discovered from /data/config.json rather than assumed: APPTAIL_UI_ADDR is only a
# request, and under host networking a probe of a hardcoded 8377 could answer from the
# host's own instance. start-period is 30s because tsnet enrollment routinely exceeds
# 10s against a cold volume.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
	CMD ["app-tail", "health"]
ENTRYPOINT ["app-tail"]
CMD ["run"]
