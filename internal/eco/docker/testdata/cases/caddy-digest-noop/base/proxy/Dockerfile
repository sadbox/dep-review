FROM golang:1.27@sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0 AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /caddy .

FROM caddy:2.11.9@sha256:0c2243efcf437ab7f7a978f1027fcf0d4f9be8a75df27b1b3fbc5dbe0ffa8cf0 AS caddy
COPY --from=builder /caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
