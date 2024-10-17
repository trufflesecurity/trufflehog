#!/usr/bin/env bash

# Parse the last argument into an array of extra_args.
mapfile -t extra_args < <(bash -c "for arg in ${*: -1}; do echo \$arg; done")

# Directories might be owned by a user other than root
git config --global --add safe.directory '*'

if [[ $# -eq 0 ]]; then
  /usr/bin/trufflehog --help
else
  /usr/bin/trufflehog "${@: 1: $#-1}" "${extra_args[@]}"
fi
