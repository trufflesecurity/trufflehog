# TruffleHog

# Join The Slack
Have questions? Feedback? Jump in slack and hang out with us

https://join.slack.com/t/trufflehog-community/shared_invite/zt-pw2qbi43-Aa86hkiimstfdKH9UCpPzQ

## Installation

Several options:

### 1. Go
`go install github.com/trufflesecurity/trufflehog2.git@latest`

### 2. [Release binaries](https://github.com/trufflesecurity/trufflehog2/releases)

### 3. Docker (TODO)
`docker run ...`

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
