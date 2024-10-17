#!/bin/bash

set -eux

for pbfile in $(ls proto/); do
    mod=${pbfile%%.proto}
    protoc -I proto/ \
        -I ${GOPATH}/src \
        -I /usr/local/include \
        -I ${GOPATH}/src/github.com/envoyproxy/protoc-gen-validate \
        --go_out=plugins=grpc:./pkg/pb/${mod}pb --go_opt=paths=source_relative \
        --validate_out="lang=go,paths=source_relative:./pkg/pb/${mod}pb" \
        proto/${mod}.proto
done

for pbfile in $(ls pkg/analyzer/proto/); do
    mod=${pbfile%%.proto}
    mkdir -p "./pkg/analyzer/pb/${mod}pb"
    protoc -I pkg/analyzer/proto/ \
        -I ${GOPATH}/src \
        -I /usr/local/include \
        -I ${GOPATH}/src/github.com/envoyproxy/protoc-gen-validate \
        --go_out=plugins=grpc:./pkg/analyzer/pb/${mod}pb --go_opt=paths=source_relative \
        --validate_out="lang=go,paths=source_relative:./pkg/analyzer/pb/${mod}pb" \
        pkg/analyzer/proto/${mod}.proto
done
