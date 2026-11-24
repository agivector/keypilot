FROM golang:1.24-alpine AS builder

WORKDIR /workspace

COPY server/go.mod ./go.mod
RUN go mod download

COPY server/ ./

RUN go test ./... \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/keypilot ./cmd/keypilot

FROM alpine:3.21

RUN addgroup -S keypilot \
    && adduser -S -D -H -u 10001 -G keypilot keypilot \
    && mkdir -p /data \
    && chown -R keypilot:keypilot /data

COPY --from=builder /out/keypilot /usr/local/bin/keypilot

ENV KEYPILOT_ADDR=:8080
ENV KEYPILOT_DATA_FILE=/data/keypilot.json

USER keypilot:keypilot

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/readyz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/keypilot"]
