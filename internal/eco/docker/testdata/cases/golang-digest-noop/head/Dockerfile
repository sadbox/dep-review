# syntax=docker/dockerfile:1
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS assets
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
RUN npx esbuild in.js --bundle --outfile=/app/app.js

FROM golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS go-builder
WORKDIR /src
COPY . .
COPY --from=assets /app/app.js ./static/app.js
RUN CGO_ENABLED=0 go build -trimpath -o /bin/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=go-builder /bin/app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]
