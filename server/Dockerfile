# Build stage. The relay is pure Go, so a static binary needs nothing at
# runtime beyond a writable directory for the SQLite file.
FROM golang:1.24-alpine AS build

WORKDIR /src

# Dependencies first so a source-only change does not re-download modules.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is off: modernc.org/sqlite is a pure-Go implementation, which keeps the
# final image on a scratch-like base with no libc to match.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/veil-relay ./...

# Runtime stage.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /data
COPY --from=build /out/veil-relay /usr/local/bin/veil-relay

ENV VEIL_ADDR=":8080" \
    VEIL_DB="/data/veil.db"

EXPOSE 8080
USER nonroot:nonroot
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/veil-relay"]
