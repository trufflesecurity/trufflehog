FROM golang:bullseye as builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . . 
RUN CGO_ENABLED=0 go build -a -o trufflehog main.go

FROM alpine:3.15
RUN apk add --no-cache git
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/trufflehog /usr/bin/trufflehog
ENTRYPOINT ["/usr/bin/trufflehog"]
