FROM golang:bullseye as builder
RUN mkdir /build
COPY . /build
WORKDIR /build
RUN CGO_ENABLED=0 go build -a -o trufflehog main.go

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/trufflehog /usr/bin/trufflehog
ENTRYPOINT ["/usr/bin/trufflehog"]