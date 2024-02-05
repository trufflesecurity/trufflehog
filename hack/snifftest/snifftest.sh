#!/usr/bin/env bash

REPO_ARRAY=(
        "https://github.com/Netflix/Hystrix.git"
        # "https://github.com/facebook/flow.git"
        # "https://github.com/Netflix/vizceral.git"
        # "https://github.com/Netflix/metaflow.git"
        # "https://github.com/Netflix/dgs-framework.git"
        # "https://github.com/Netflix/vector.git"
        # "https://github.com/expressjs/express.git"
        # "https://github.com/Azure/azure-sdk-for-net"
        # "https://github.com/Azure/azure-cli"
)
REPOS=$(printf "%s," "${REPO_ARRAY[@]}" | cut -d "," -f 1-${#REPO_ARRAY[@]})
go run hack/snifftest/main.go scan --exclude privatekey --exclude uri --exclude github_old --repo "$REPOS" --detector all --print  --fail-threshold 99