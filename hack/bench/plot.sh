#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Usage: $0 <repository to clone> <number_of_versions_back_to_test>"
  exit 1
fi

# Get the number of versions back to test from command line argument
num_versions="$2"

test_repo="$1"

bash hack/bench/versions.sh $test_repo $num_versions | tee hack/bench/plot.txt

gnuplot hack/bench/plot.gp
