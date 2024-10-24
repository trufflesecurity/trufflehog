# Dockerfile for building the trufflehog application

# Build stage: Use golang:bullseye as the base image
FROM --platform=${BUILDPLATFORM} golang:bullseye as builder

# Set the working directory
WORKDIR /build

# Copy the entire source code into the container
COPY . . 

# Set environment variable to disable CGO
ENV CGO_ENABLED=0

# Set target OS and architecture
ARG TARGETOS TARGETARCH

# Build the trufflehog binary
RUN  --mount=type=cache,target=/go/pkg/mod \
     --mount=type=cache,target=/root/.cache/go-build \
     GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o trufflehog .

# Final stage: Use alpine:3.20 as the base image
FROM alpine:3.20

# Install necessary dependencies
RUN apk add --no-cache bash git openssh-client ca-certificates rpm2cpio binutils cpio \
    && rm -rf /var/cache/apk/* && update-ca-certificates

# Copy the trufflehog binary from the build stage
COPY --from=builder /build/trufflehog /usr/bin/trufflehog

# Copy the entrypoint script
COPY entrypoint.sh /etc/entrypoint.sh

# Make the entrypoint script executable
RUN chmod +x /etc/entrypoint.sh

# Set the entrypoint of the container
ENTRYPOINT ["/etc/entrypoint.sh"]
