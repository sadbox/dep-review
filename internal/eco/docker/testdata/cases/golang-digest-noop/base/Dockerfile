# syntax=docker/dockerfile:1
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS assets
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
RUN npx esbuild in.js --bundle --outfile=/app/app.js

FROM golang:1.27@sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0 AS go-builder
WORKDIR /src
COPY . .
COPY --from=assets /app/app.js ./static/app.js
RUN CGO_ENABLED=0 go build -trimpath -o /bin/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=go-builder /bin/app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]
