#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Usage: $0 <repository to clone> <number_of_versions_back_to_test>"
  exit 1
fi

# Get the number of versions back to test from command line argument
num_versions="$2"

test_repo="$1"

num_iterations=5

# Create a temporary folder to clone the repository
repo_tmp=$(mktemp -d)
# Set up a trap to remove the temporary folder on exit or failure
trap "rm -rf $repo_tmp" EXIT
# Clone the test repository to a temporary folder
git clone --quiet "$test_repo" $repo_tmp


# Get list of git tags, sorted from newest to oldest
tags=$(echo $(git describe --tags --always --dirty --match='v*') $(git tag --sort=-creatordate))

# Counter to keep track of number of tags checked out
count=0


# Loop over tags and checkout each one in turn, up to the specified number of versions
for tag in $tags
do
  if [[ $count -eq $num_versions ]]; then
      break
  fi

  # Skip RC tags
  if [[ $tag == *"rc"* ]]; then
    continue
  fi

  # Skip alpha tags
  if [[ $tag == *"alpha"* ]];  then
    continue
  fi

  # Use git checkout with the quiet flag to suppress output
  git checkout $tag --quiet

  # Run make install with suppressed output
  make install > /dev/null

  # Initialize the variable to store the sum of user times
  user_time_sum=0

  # Run each iteration 5 times and calculate the average user time
  for i in {1..$num_iterations}
  do
    # Run trufflehog with suppressed output and capture user time with /usr/bin/time
    tmpfile=$(mktemp)
    /usr/bin/time -o $tmpfile trufflehog git "file://$repo_tmp" --no-verification --no-update >/dev/null 2>&1
    time_output=$(cat $tmpfile)
    rm $tmpfile

    # Extract the user time from the output
    user_time=$(echo $time_output | awk '{print $3}')

    # Add the user time to the sum
    user_time_sum=$(echo "$user_time_sum + $user_time" | bc)
  done

  # Calculate the average user time
  average_user_time=$(echo "scale=3; $user_time_sum / $num_iterations" | bc)

  # Print the average user time output for this iteration in the specified format
  echo "$tag: $average_user_time"

  # Increment the counter
  count=$((count+1))
done
