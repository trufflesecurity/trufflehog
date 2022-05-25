<p align="center">
  <img alt="GoReleaser Logo" src="https://storage.googleapis.com/trufflehog-static-sources/pixel_pig.png" height="140" />
  <h2 align="center">TruffleHog</h2>
  <p align="center">Find leaked credentials.</p>
</p>

---

<center>

[![CI Status](https://github.com/trufflesecurity/trufflehog/actions/workflows/release.yml/badge.svg)](https://github.com/trufflesecurity/trufflehog/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/trufflesecurity/trufflehog/v3)](https://goreportcard.com/report/github.com/trufflesecurity/trufflehog/v3)
[![License](https://img.shields.io/badge/license-AGPL--3.0-brightgreen)](/LICENSE)
[![Total Detectors](https://shields-staging.herokuapp.com/github/directory-file-count/trufflesecurity/truffleHog/pkg/detectors?label=Total%20Detectors&type=dir)](/pkg/detectors) <!-- Badge must be run from staging, see badges/shields#5967 -->

</center>

---

## Join The Slack
Have questions? Feedback? Jump in slack and hang out with us

https://join.slack.com/t/trufflehog-community/shared_invite/zt-pw2qbi43-Aa86hkiimstfdKH9UCpPzQ


## Demo

![GitHub scanning demo](https://storage.googleapis.com/truffle-demos/non-interactive.svg)

```bash
docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
```

# What's new in v3?

TruffleHog v3 is a complete rewrite in Go with many new powerful features.

- We've **added over 700 credential detectors that support active verification against their respective APIs**.
- We've also added native **support for scanning GitHub, GitLab, filesystems, and S3**.
- **Instantly verify private keys** against millions of github users and **billions** of TLS certificates using our [Driftwood](https://trufflesecurity.com/blog/driftwood) technology.


## What is credential verification?
For every potential credential that is detected, we've painstakingly implemented programatic verification against the API that we think it belongs to. Verification eliminates false positives. For example, the [AWS credential detector](pkg/detectors/aws/aws.go) performs a `GetCallerIdentity` API call against the AWS API to verify if an AWS credential is active.

## Installation

Several options:

### 1. Go
```
git clone https://github.com/trufflesecurity/trufflehog.git

cd trufflehog; go install
```

### 2. [Release binaries](https://github.com/trufflesecurity/trufflehog/releases)

### 3. Docker


> Note: Apple M1 hardware users should run with `docker run --platform linux/arm64` for better performance.

#### **Most users**

```bash
docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
```

#### **Apple M1 users**

The `linux/arm64` image is better to run on the M1 than the amd64 image.
Even better is running the native darwin binary avilable, but there is not container image for that.

```bash
docker run --platform linux/arm64 -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys 
```

### 4. Pip (help wanted)

It's possible to distribute binaries in pip wheels.

Here is an example of a [project that does it](https://github.com/Yelp/dumb-init).

Help with setting up this packaging would be appreciated!

### 5. Brew

```bash
brew tap trufflesecurity/trufflehog
brew install trufflehog
```

## Usage

TruffleHog has a sub-command for each source of data that you may want to scan:

- git
- github
- gitlab
- S3
- filesystem
- syslog
- file and stdin (coming soon)

Each subcommand can have options that you can see with the `-h` flag provided to the sub command:

```
$ trufflehog git --help
usage: TruffleHog git [<flags>] <uri>

Find credentials in git repositories.

Flags:
      --help                     Show context-sensitive help (also try --help-long and --help-man).
      --debug                    Run in debug mode
      --version                  Prints trufflehog version.
  -j, --json                     Output in JSON format.
      --json-legacy              Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.
      --concurrency=1            Number of concurrent workers.
      --no-verification          Don't verify the results.
      --only-verified            Only output verified results.
      --print-avg-detector-time  Print the average time spent on each detector.
      --no-update                Don't check for updates.
  -i, --include-paths=INCLUDE-PATHS
                                 Path to file with newline separated regexes for files to include in scan.
  -x, --exclude-paths=EXCLUDE-PATHS
                                 Path to file with newline separated regexes for files to exclude in scan.
      --since-commit=SINCE-COMMIT
                                 Commit to start scan from.
      --branch=BRANCH            Branch to scan.
      --max-depth=MAX-DEPTH      Maximum depth of commits to scan.
      --allow                    No-op flag for backwards compat.
      --entropy                  No-op flag for backwards compat.
      --regex                    No-op flag for backwards compat.

Args:
  <uri>  Git repository URL. https:// or file:// schema expected.
```

For example, to scan a  `git` repository, start with

```
$ trufflehog git https://github.com/trufflesecurity/trufflehog.git
```

Exit Codes:
- 0: No errors and no results were found.
- 1: An error was encountered. Sources may not have completed scans.
- 183: No errors were encountered, but results were found. Will only be returned if `--fail` flag is used.

#### Scanning an organization

Try scanning an entire GitHub organization with the following:

```bash
docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
```

### TruffleHog OSS Github Action

```yaml
- name: TruffleHog OSS
  uses: trufflesecurity/trufflehog@main
  with:
    # Repository path
    path: 
    # Start scanning from here (usually main branch).
    base: 
    # Scan commits until here (usually dev branch).
    head: # optional
```

The TruffleHog OSS Github Action can be used to scan a range of commits for leaked credentials. The action will fail if
any results are found.

For example, to scan the contents of pull requests you could use the following workflow:
```yaml
name: Leaked Secrets Scan
on: [pull_request]
jobs:
  TruffleHog:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@v3.4.3
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

## Contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].


<a href="https://github.com/trufflesecurity/trufflehog/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=trufflesecurity/trufflehog" />
</a>


## Contributing

Contributions are very welcome! Please see our [contribution guidelines first](CONTRIBUTING.md).

We no longer accept contributions to TruffleHog v2, but that code is available in the `v2` branch.

### Adding new secret detectors

We have published some [documentation and tooling to get started on adding new secret detectors](hack/docs/Adding_Detectors_external.md). Let's improve detection together!

## License Change

Since v3.0, TruffleHog is released under a AGPL 3 license, included in [`LICENSE`](LICENSE). TruffleHog v3.0 uses none of the previous codebase, but care was taken to preserve backwards compatibility on the command line interface. The work previous to this release is still available licensed under GPL 2.0 in the history of this repository and the previous package releases and tags. A completed CLA is required for us to accept contributions going forward.
