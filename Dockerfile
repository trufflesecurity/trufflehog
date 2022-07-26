FROM --platform=${BUILDPLATFORM} golang:bullseye as builder

WORKDIR /build
COPY . . 
ENV CGO_ENABLED=0
ARG TARGETOS TARGETARCH
RUN  --mount=type=cache,target=/go/pkg/mod \
     --mount=type=cache,target=/root/.cache/go-build \
     GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o trufflehog .

FROM alpine:3.15
RUN apk add --no-cache git
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/trufflehog /usr/bin/trufflehog
ENTRYPOINT ["/usr/bin/trufflehog"]

