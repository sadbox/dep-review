FROM golang:1.27@sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0 AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /caddy .

FROM caddy:2.11.9@sha256:4e2425f6009577e7c651010f16679c28f7d12df3e7b1914f941a7a3370746b3c AS caddy
COPY --from=builder /caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
