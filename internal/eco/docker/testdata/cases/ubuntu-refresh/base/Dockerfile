FROM golang:1.27@sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0 AS builder
WORKDIR /src
COPY . .
RUN go build -o /bin/web .

FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
WORKDIR /bin
COPY --from=builder /bin/web ./
CMD ["/bin/web"]
