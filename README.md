<p align="center">
  <img alt="GoReleaser Logo" src="https://storage.googleapis.com/trufflehog-static-sources/pixel_pig.png" height="140" />
  <h2 align="center">TruffleHog</h2>
  <p align="center">Find leaked credentials.</p>
</p>

---

<div align="center">

[![CI Status](https://github.com/trufflesecurity/trufflehog/actions/workflows/release.yml/badge.svg)](https://github.com/trufflesecurity/trufflehog/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/trufflesecurity/trufflehog/v3)](https://goreportcard.com/report/github.com/trufflesecurity/trufflehog/v3)
[![License](https://img.shields.io/badge/license-AGPL--3.0-brightgreen)](/LICENSE)
[![Total Detectors](https://img.shields.io/github/directory-file-count/trufflesecurity/truffleHog/pkg/detectors?label=Total%20Detectors&type=dir)](/pkg/detectors)

</div>

---

## Join The Slack
Have questions? Feedback? Jump in slack and hang out with us

https://join.slack.com/t/trufflehog-community/shared_invite/zt-pw2qbi43-Aa86hkiimstfdKH9UCpPzQ


## Demo

![GitHub scanning demo](https://storage.googleapis.com/truffle-demos/non-interactive.svg)

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
```

## Examples

### Example 1: Scan a repo for only verified secrets

Command:

```bash
trufflehog git https://github.com/trufflesecurity/test_keys --only-verified
```

Expected output:
```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAYVP4CIPPERUVIFXG
Line: 4
Commit: fbc14303ffbf8fb1c2c1914e8dda7d0121633aca
File: keys
Email: counter <counter@counters-MacBook-Air.local>
Repository: https://github.com/trufflesecurity/test_keys
Timestamp: 2022-06-16 10:17:40 -0700 PDT
...
```

### Example 2: Scan a GitHub Org for only verified secrets

```bash
trufflehog github --org=trufflesecurity --only-verified
```

### Example 3: Scan a GitHub Repo for only verified keys and get JSON output

Command:

```bash
trufflehog git https://github.com/trufflesecurity/test_keys --only-verified --json
```

Expected output:
```
{"SourceMetadata":{"Data":{"Git":{"commit":"fbc14303ffbf8fb1c2c1914e8dda7d0121633aca","file":"keys","email":"counter \u003ccounter@counters-MacBook-Air.local\u003e","repository":"https://github.com/trufflesecurity/test_keys","timestamp":"2022-06-16 10:17:40 -0700 PDT","line":4}}},"SourceID":0,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":2,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"AKIAYVP4CIPPERUVIFXG","Redacted":"AKIAYVP4CIPPERUVIFXG","ExtraData":{"account":"595918472158","arn":"arn:aws:iam::595918472158:user/canarytokens.com@@mirux23ppyky6hx3l6vclmhnj","user_id":"AIDAYVP4CIPPJ5M54LRCY"},"StructuredData":null}
...
```

### Example 4: Scan an S3 bucket for verified keys

```bash
trufflehog s3 --bucket=<bucket name> --only-verified
```

### FAQ

+ All I see is `🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷` and the program exits, what gives?
  + That means no secrets were detected
+ Why is the scan is taking a long time when I scan a GitHub org
  + Unauthenticated GitHub scans have rate limits. To improve your rate limits, include the `--token` flag with a personal access token
+ It says a private key was verified, what does that mean?
  + Check out our Driftwood blog post to learn how to do this, in short we've confirmed the key can be used live for SSH or SSL [Blog post](https://trufflesecurity.com/blog/driftwood-know-if-private-keys-are-sensitive/)


### Example 5: Scan a Github Repo using SSH authentication in docker

```bash
docker run --rm -v "$HOME/.ssh:/root/.ssh:ro" trufflesecurity/trufflehog:latest git ssh://github.com/trufflesecurity/test_keys
```

# What's new in v3?

TruffleHog v3 is a complete rewrite in Go with many new powerful features.

- We've **added over 700 credential detectors that support active verification against their respective APIs**.
- We've also added native **support for scanning GitHub, GitLab, filesystems, S3, and Circle CI**.
- **Instantly verify private keys** against millions of github users and **billions** of TLS certificates using our [Driftwood](https://trufflesecurity.com/blog/driftwood) technology.


## What is credential verification?
For every potential credential that is detected, we've painstakingly implemented programmatic verification against the API that we think it belongs to. Verification eliminates false positives. For example, the [AWS credential detector](pkg/detectors/aws/aws.go) performs a `GetCallerIdentity` API call against the AWS API to verify if an AWS credential is active.

## Installation

Several options:

### 1. Go
```bash
git clone https://github.com/trufflesecurity/trufflehog.git

cd trufflehog; go install
```

### 2. [Release binaries](https://github.com/trufflesecurity/trufflehog/releases)

### 3. Docker


> Note: Apple M1 hardware users should run with `docker run --rm --platform linux/arm64` for better performance.

#### **Most users**

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
```

#### **Apple M1 users**

The `linux/arm64` image is better to run on the M1 than the amd64 image.
Even better is running the native darwin binary available, but there is no container image for that.

```bash
docker run --rm --platform linux/arm64 -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
```

### 4. Pip (help wanted)

It's possible to distribute binaries in pip wheels.

Here is an example of a [project that does it](https://github.com/Yelp/dumb-init).

Help with setting up this packaging would be appreciated!

### 5. Brew

```bash
brew install trufflesecurity/trufflehog/trufflehog
```

## Usage

TruffleHog has a sub-command for each source of data that you may want to scan:

- git
- github
- gitlab
- S3
- filesystem
- syslog
- circleci
- file and stdin (coming soon)

Each subcommand can have options that you can see with the `--help` flag provided to the sub command:

```
$ trufflehog git --help
usage: TruffleHog git [<flags>] <uri>

Find credentials in git repositories.

Flags:
      --help                     Show context-sensitive help (also try --help-long and --help-man).
      --debug                    Run in debug mode.
      --trace                    Run in trace mode.
  -j, --json                     Output in JSON format.
      --json-legacy              Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.
      --concurrency=10           Number of concurrent workers.
      --no-verification          Don't verify the results.
      --only-verified            Only output verified results.
      --filter-unverified        Only output first unverified result per chunk per detector if there are more than one results.
      --config=CONFIG            Path to configuration file.
      --print-avg-detector-time  Print the average time spent on each detector.
      --no-update                Don't check for updates.
      --fail                     Exit with code 183 if results are found.
      --version                  Show application version.

Args:
  <uri>  Git repository URL. https://, file://, or ssh:// schema expected.
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
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
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
    # Extra args to be passed to the trufflehog cli.
    extra_args: --debug --only-verified
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
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug --only-verified
```

### Precommit Hook

Trufflehog can be used in a precommit hook to prevent credentials from leaking before they ever leave your computer.
An example `.pre-commit-config.yaml` is provided (see [pre-commit.com](https://pre-commit.com/) for installation).

```yaml
repos:
- repo: local
  hooks:
    - id: trufflehog
      name: TruffleHog
      description: Detect secrets in your data.
      entry: bash -c 'trufflehog git file://. --since-commit HEAD --only-verified --fail'
      # For running trufflehog in docker, use the following entry instead:
      # entry: bash -c 'docker run --rm -v "$(pwd):/workdir" -i --rm trufflesecurity/trufflehog:latest git file:///workdir --since-commit HEAD --only-verified --fail'
      language: system
      stages: ["commit", "push"]
```

## Regex Detector (alpha)

Trufflehog supports detection and verification of custom regular expressions.
For detection, at least one **regular expression** and **keyword** is required.
A **keyword** is a fixed literal string identifier that appears in or around
the regex to be detected. To allow maximum flexibility for verification, a
webhook is used containing the regular expression matches.

Trufflehog will send a JSON POST request containing the regex matches to a
configured webhook endpoint. If the endpoint responds with a `200 OK` response
status code, the secret is considered verified.

**NB:** This feature is alpha and subject to change.

### Regex Detector Example

```yaml
# config.yaml
detectors:
- name: hog detector
  keywords:
  - hog
  regex:
    adjective: hogs are (\S+)
  verify:
  - endpoint: http://localhost:8000/
    # unsafe must be set if the endpoint is HTTP
    unsafe: true
    headers:
    - 'Authorization: super secret authorization header'
```

```
$ trufflehog filesystem --directory /tmp --config config.yaml --only-verified
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: hogs are cool
File: /tmp/hog-facts.txt
```

#### Verification Server Example (Python)

Unless you run a verification server, secrets found by the custom regex
detector will be unverified. Here is an example Python implementation of a
verification server for the above `config.yaml` file.

```python
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

AUTH_HEADER = 'super secret authorization header'


class Verifier(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        try:
            if self.headers['Authorization'] != AUTH_HEADER:
                self.send_response(401)
                self.end_headers()
                return

            # read the body
            length = int(self.headers['Content-Length'])
            request = json.loads(self.rfile.read(length))
            self.log_message("%s", request)

            # check the match
            if request['hog detector']['adjective'][-1] == 'cool':
                self.send_response(200)
                self.end_headers()
            else:
                # any other response besides 200
                self.send_response(406)
                self.end_headers()
        except Exception:
            self.send_response(400)
            self.end_headers()


with HTTPServer(('', 8000), Verifier) as server:
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
```

## Use as a library

Currently, trufflehog is in heavy development and no guarantees can be made on
the stability of the public APIs at this time.

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


## Enterprise product

Are you interested in continously monitoring your Git, Jira, Slack, Confluence, etc.. for credentials? We have an enterprise product that can help. Reach out here to learn more https://trufflesecurity.com/contact/

We take the revenue from the enterprise product to fund more awesome open source projects that the whole community can benefit from.
