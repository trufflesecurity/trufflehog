#!/bin/bash

set -eux

for pbfile in $(ls proto/); do
    mod=${pbfile%%.proto}
    # A "<pkg>_types.proto" file shares a Go package with "<pkg>.proto", so it
    # generates into the same directory.
    pkgdir=${mod%_types}
    protoc -I proto/ \
        -I ${GOPATH}/src \
        -I /usr/local/include \
        -I ${GOPATH}/src/github.com/envoyproxy/protoc-gen-validate \
        --go_out=plugins=grpc:./pkg/pb/${pkgdir}pb --go_opt=paths=source_relative \
        --validate_out="lang=go,paths=source_relative:./pkg/pb/${pkgdir}pb" \
        proto/${mod}.proto
done
