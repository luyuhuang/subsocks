FROM golang:1.15-alpine as builder

WORKDIR /subsocks
COPY . .

ENV GO111MODULE=on
RUN go build .

FROM alpine:latest

WORKDIR /subsocks
COPY --from=builder /subsocks/subsocks .

ENTRYPOINT ["/subsocks/subsocks"]
