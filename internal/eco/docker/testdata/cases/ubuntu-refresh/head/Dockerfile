FROM golang:1.27@sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0 AS builder
WORKDIR /src
COPY . .
RUN go build -o /bin/web .

FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
WORKDIR /bin
COPY --from=builder /bin/web ./
CMD ["/bin/web"]
