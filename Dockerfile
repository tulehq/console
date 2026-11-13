# syntax=docker/dockerfile:1

# The build stage runs on the builder's own platform and cross-compiles, so a
# multi-platform build needs no emulation. Nothing needs cgo.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X tule.dev/console/internal/util/buildinfo.Version=${VERSION}" \
    -o /out/tule-console ./cmd

# Alpine rather than distroless, for a shell to debug in and wget for the
# health check.
FROM alpine:3.24
# 65532 is the distroless nonroot user's UID and GID, as in the other tule
# service images.
RUN addgroup -S -g 65532 nonroot && adduser -S -u 65532 -G nonroot nonroot
# gas/config reads .env from the working directory and refuses to when that is
# /, so the server must not start there.
WORKDIR /home/nonroot
LABEL org.opencontainers.image.source=https://github.com/tulehq/console \
      org.opencontainers.image.description="Web console for the Tule services: browse each one and run the everyday actions" \
      org.opencontainers.image.licenses=MIT
COPY --from=build /out/tule-console /tule-console

# At least one TULE_Console_*Endpoint must be set at run time; the console
# shows the services it is pointed at and has nothing to show without one.
# It holds no data: sessions live in memory, so a restart signs everyone out.
ENV TULE_GasEnv=development

USER nonroot
EXPOSE 9070
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${TULE_Server_Port:-9070}/_ready" || exit 1
ENTRYPOINT ["/tule-console"]
