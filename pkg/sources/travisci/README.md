# Travis CI Source

## Overview

The Travis CI source lets TruffleHog scan Travis CI job logs for secrets, credentials, and sensitive data. It scans every repository the provided API token can see, walking each repository's build history and reading the log of every job.

## Travis CI Fundamentals

### What does this source scan?

This source reads the text logs that Travis CI keeps for each job. Anything printed during a job, such as output from build commands, can end up in these logs. It does not read your repository code, your `.travis.yml` file, or the settings and environment variables stored in Travis CI.

### Key Travis CI Terminology

| Term | Description |
|------|-------------|
| **Repository** | A code repository that is connected to Travis CI |
| **Build** | One run of Travis CI for a repository, started by a push or a pull request |
| **Job** | One part of a build. A build can have many jobs, for example one per language version |
| **Log** | The text output of a single job |
| **API Token** | A secret that lets a tool call the Travis CI API as you |

## Features

- **Whole Account Scanning**: Finds every repository the token can see and scans them all
- **Full Build History**: Pages through all builds of each repository, not only the latest
- **Job Log Scanning**: Reads the log of every job in every build
- **Useful Result Details**: Each result carries the owner, repository, build number, job number, and a link to the job
- **Parallel Repositories**: Several repositories can be scanned at the same time

## Configuration

### Authentication Methods

#### API Token

**CLI Usage:**
```bash
trufflehog travisci --token YOUR_TRAVIS_CI_TOKEN
```

On the CLI, the token can also be set with the `TRAVISCI_TOKEN` environment variable instead of `--token`. The CLI requires a token one way or the other.

Before scanning, TruffleHog asks Travis CI who the token belongs to. If that call fails, the scan stops. TruffleHog also hides the token in its own log output.

### Where Does It Connect?

TruffleHog always talks to `https://api.travis-ci.com/`. This address is fixed in the code. There is no flag to point it at another Travis CI server, such as a self-hosted one.

### YAML Configuration

This source cannot be used from a `--config` YAML file. The YAML loader has no case for Travis CI, so use the CLI command above.

### Choosing What to Scan

There are no options for this. The source scans every repository that the token can list. There is no way to include or exclude a repository, a branch, or a build.

### Number of Workers

There is no Travis CI specific worker setting. Repositories are scanned as separate units, and the global `--concurrency` flag sets how many of them are scanned at the same time. Inside one repository, builds, jobs, and logs are fetched one at a time.

```bash
trufflehog travisci --token YOUR_TRAVIS_CI_TOKEN --concurrency 4
```

## How Scanning Works

### Scanning Process

1. **Check the Token**: Asks Travis CI for the current user. If this fails, the scan stops
2. **List Repositories**: Reads the repository list 100 at a time until a page comes back empty. If the very first page fails, the scan stops. If a later page fails, the error is reported and the listing carries on
3. **Scan Each Repository**: For each repository, reads its builds 100 at a time until a page comes back empty
4. **Read Jobs**: For each build, lists its jobs
5. **Read Logs**: For each job, downloads its log and sends it to the detection engine as one piece of data

### What Gets Scanned

- The full text log of every job in every build of every repository the token can list

### What Doesn't Get Scanned

- Repository code and `.travis.yml` files
- Environment variables and other settings stored in Travis CI
- Anything on a server other than `https://api.travis-ci.com/`
- Jobs whose log could not be downloaded. The error is reported and the job is skipped

### Result Details

Each result carries these details:

| Detail | Meaning |
|--------|---------|
| Username | The login of the job's owner |
| Repository | The repository name |
| Build number | The build number |
| Job number | The job number |
| Link | A link to the job, in the form `https://app.travis-ci.com/github/<owner>/<repository>/jobs/<job id>` |
| Public | `true` when the repository is not private |

### Error Handling

- If listing a page of a repository's builds fails, the error is reported and TruffleHog moves on to the next page. After 5 failed pages in a row, it stops scanning that repository and reports a fatal error for it. A successful page resets the count
- If listing the jobs of a build fails, or downloading a job log fails, the error is reported and scanning goes on
- If a build has no jobs, TruffleHog stops looking at the rest of that page of 100 builds and moves on to the next page. Builds after it on the same page are not scanned

## Usage Examples

### Scan Everything the Token Can See

```bash
trufflehog travisci --token YOUR_TRAVIS_CI_TOKEN
```

### Use the Environment Variable

```bash
export TRAVISCI_TOKEN=YOUR_TRAVIS_CI_TOKEN
trufflehog travisci
```

### Scan More Repositories at Once

```bash
trufflehog travisci --token YOUR_TRAVIS_CI_TOKEN --concurrency 8
```

### JSON Output, Only Verified Results

```bash
trufflehog travisci --token YOUR_TRAVIS_CI_TOKEN --json --results=verified
```

## Troubleshooting

### Common Issues

**Issue**: `required flag(s) --token not provided`
**Solution**: Pass `--token` or set the `TRAVISCI_TOKEN` environment variable.

---

**Issue**: `token is empty`
**Solution**: The token value was blank. Provide a real token.

---

**Issue**: `error getting testing travis client`
**Solution**: Travis CI rejected the token or could not be reached. Check that the token is valid and belongs to an account on `travis-ci.com`.

---

**Issue**: `error listing repositories`
**Solution**: The first request for the repository list failed. Check the token and your network connection.

---

**Issue**: `encountered too many errors listing builds, aborting`
**Solution**: Listing builds for one repository failed on 5 pages in a row, so TruffleHog stopped scanning that repository. Check the token's access to it, then run the scan again.

---

**Issue**: A repository, build, or job is missing from the results
**Solution**: The token can only list what its account can see. Also, a build with no jobs ends the scan of the rest of its page of 100 builds, and a job whose log cannot be downloaded is skipped.
