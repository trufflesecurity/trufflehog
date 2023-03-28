#!/usr/bin/env bash

# Parse the last argument into an array of extra_args.
mapfile -t extra_args < <(bash -c "for arg in ${*: -1}; do echo \$arg; done")

results=$(/usr/bin/trufflehog "${@: 1: $#-1}" "${extra_args[@]}" | tee /dev/tty)
echo "results=$results" >> $GITHUB_OUTPUT
