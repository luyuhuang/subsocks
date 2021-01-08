FROM golang:1.15-alpine as builder

ARG VERSION
WORKDIR /subsocks
COPY . .

ENV GO111MODULE=on
RUN go build -ldflags "-X main.Version=${VERSION}"

FROM alpine:latest

WORKDIR /subsocks
COPY --from=builder /subsocks/subsocks .

ENTRYPOINT ["/subsocks/subsocks"]
