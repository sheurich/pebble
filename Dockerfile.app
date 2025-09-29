# Build a single Go command binary using the golang image and emit a minimal final image.
# Usage: docker build --build-arg APP=pebble -f Dockerfile.app .

FROM --platform=${BUILDPLATFORM} golang:1-bookworm AS builder
ARG APP=pebble
WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build requested app
COPY . .
RUN mkdir -p /out \
    && CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o /out/${APP} ./cmd/${APP}

FROM scratch AS final
ARG APP=pebble
# Copy the built binary from the builder
COPY --from=builder /out/${APP} /app
ENTRYPOINT ["/app"]
