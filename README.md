# TruffleHog

[![CI Status](https://github.com/trufflesecurity/trufflehog2/workflows/release/badge.svg)](https://github.com/trufflesecurity/trufflehog2/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/trufflesecurity/trufflehog2)](https://goreportcard.com/report/github.com/trufflesecurity/trufflehog2)
[![Docker Hub Build Status](https://img.shields.io/docker/cloud/build/trufflesecurity/trufflehog2.svg)](https://hub.docker.com/r/trufflesecurity/trufflehog2/)
![GitHub](https://img.shields.io/github/license/trufflesecurity/trufflehog2)

## Join The Slack
Have questions? Feedback? Jump in slack and hang out with us

https://join.slack.com/t/trufflehog-community/shared_invite/zt-pw2qbi43-Aa86hkiimstfdKH9UCpPzQ

## Installation

Several options:

### 1. Go
`go install github.com/trufflesecurity/trufflehog2.git@latest`

### 2. [Release binaries](https://github.com/trufflesecurity/trufflehog2/releases)

### 3. Docker
```bash
$ docker run -v "$PWD:/pwd" ghcr.io/trufflesecurity/trufflehog2:latest github --repo https://github.com/dustin-decker/secretsandstuff.git     
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found verified result 🐷🔑
Detector Type: AWS
File: aws
Link: https://github.com/dustin-decker/secretsandstuff/blob/90c75f884c65dc3638ca1610bd9844e668f213c2/aws
Repository: https://github.com/dustin-decker/secretsandstuff.git
Commit: 90c75f884c65dc3638ca1610bd9844e668f213c2
Email: dustindecker@protonmail.com

Found unverified result 🐷🔑❓
Detector Type: Github
File: slack
Link: https://github.com/dustin-decker/secretsandstuff/blob/8afb0ecd4998b1179e428db5ebbcdc8221214432/slack
Repository: https://github.com/dustin-decker/secretsandstuff.git
Commit: 8afb0ecd4998b1179e428db5ebbcdc8221214432
Email: dustindecker@protonmail.com
...
```

### 4. Pip (TODO)
pip install trufflehog

### 5. Brew (TODO)
brew install trufflehog

## Usage

TruffleHog has a sub-command for each source of data that you may want to scan:

- git
- github
- gitlab
- slack
- S3

Each subcommand can have options that you can see with the `-h` flag provided to the sub command:

```
$ trufflehog git --help
usage: TruffleHog git [<flags>] <uri>

Find credentials in git repositories.

Flags:
      --help           Show context-sensitive help (also try --help-long and --help-man).
      --debug          Run in debug mode
      --json           Output in JSON format.
      --concurrency=8  Number of concurrent workers.
      --verification   Verify the results.
  -i, --include_paths=INCLUDE_PATHS  
                       Path to file with newline separated regexes for files to include in scan.
  -x, --exclude_paths=EXCLUDE_PATHS  
                       Path to file with newline separated regexes for files to exclude in scan.
      --branch=BRANCH  Branch to scan.
      --allow          No-op flag for backwards compat.
      --entropy        No-op flag for backwards compat.
      --regex          No-op flag for backwards compat.

Args:
  <uri>  Git repository URL. https:// or file:// schema expected.
```

For example, to scan a  `git` repository, start with

```
$ trufflehog git https://github.com/trufflesecurity/trufflehog2.git
```

# License Change

Since v3.0, TruffleHog is released under a AGPL 3 license, included in [`LICENSE`](LICENSE). TruffleHog v3.0 uses none of the previous codebase, but care was taken to preserve backwards compatibility on the command line interface. The work previous to this release is still available licensed under GPL 2.0 in the history of this repository and the previous package releases and tags. A completed CLA is required for us to accept contributions going forward.
