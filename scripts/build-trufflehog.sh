#!/bin/bash
set -e

echo "Building TruffleHog with custom detectors..."
echo "=============================================="

cd /root/trufflehog

# Method 1: Try building with existing vendor directory
if [ -d "vendor" ]; then
    echo "Using vendor directory..."
    CGO_ENABLED=0 go build -mod=vendor -o /tmp/trufflehog-new .
    if [ $? -eq 0 ]; then
        echo "Build successful with vendor!"
        exit 0
    fi
fi

# Method 2: Try with module mode
echo "Attempting build with go modules..."
export GO111MODULE=on
go mod download 2>/dev/null || true

# Try building without strict module checking
CGO_ENABLED=0 go build -mod=mod -o /tmp/trufflehog-new . 2>&1 | tee /tmp/build.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "Build successful!"
    echo "New binary at: /tmp/trufflehog-new"
    /tmp/trufflehog-new --version
    exit 0
else
    echo "Build failed. Checking for missing packages..."
    
    # Check if protobuf packages are missing
    if grep -q "pkg/pb" /tmp/build.log; then
        echo ""
        echo "ERROR: Protobuf packages are missing."
        echo "This usually means the repository needs protobuf generation."
        echo ""
        echo "Solutions:"
        echo "1. Use the existing binary: /usr/local/bin/trufflehog (recommended)"
        echo "2. Install from GitHub releases with your custom detectors"
        echo "3. Generate protobufs with: make protos (if Makefile supports it)"
        echo ""
        exit 1
    fi
    
    echo "See full build log at: /tmp/build.log"
    exit 1
fi

