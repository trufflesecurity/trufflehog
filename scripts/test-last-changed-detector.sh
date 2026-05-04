#!/bin/bash

set -uo pipefail

CHANGED=$(git diff --name-only --no-commit-id origin/main | grep pkg/detectors | grep -v test)
while IFS= read -r FILE; do
    DIRECTORY=$(basename $FILE ".go")
    if [ -d "pkg/detectors/$DIRECTORY" ]
    then
        echo $DIRECTORY
        go test -v "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/$DIRECTORY"
        retVal=$?
        if [ $retVal -ne 0 ]; then
           exit 1
        fi
    fi
done <<< "$CHANGED"
