#!/usr/bin/env ash

# `$*` expands the `args` supplied in an `array` individually
# or splits `args` in a string separated by whitespace.
echo /usr/bin/trufflehog $*
/usr/bin/trufflehog $*