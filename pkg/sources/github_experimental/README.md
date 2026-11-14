# GitHub Experimental Source

## Overview

The GitHub Experimental source runs experimental GitHub scans. It is an alpha release, so its behavior and flags may change. Today it has one sub-module, object discovery, which finds commits that GitHub still serves for a repository but that a normal clone does not get, and scans them for secrets, credentials, and sensitive data along with the rest of the repository.

## GitHub Experimental Fundamentals

### What does this source scan?

This source scans one GitHub repository: every commit a normal clone gets, plus hidden commits found by object discovery. A hidden commit is one that still exists on GitHub, for example from a deleted fork or a force push, but is not reachable from any branch or tag of the repository.

GitHub lets any commit in a repository's fork network be fetched by its hash, and a short hash is enough to look it up. Object discovery asks GitHub about every possible short hash to find the ones that exist.

### Key Terminology

| Term | Description |
|------|-------------|
| **Hidden commit** | A commit GitHub still serves for the repository that is not in a normal clone |
| **Short SHA** | The first few characters of a commit hash. GitHub can look up a commit by its short SHA |
| **Collision** | Two commits sharing the same short SHA, so one short SHA can't find both |
| **Collision threshold** | How many collisions the scan accepts. A lower value means longer short SHAs, more requests, and fewer missed commits |
| **Fork network** | A repository and all its forks. Commits pushed to any fork can be fetched from the others |

## Features

- **Hidden Commit Discovery**: Finds commits that GitHub serves but a normal clone misses
- **Resumable**: Results are cached on disk, so a stopped run picks up where it left off
- **Adaptive Batch Size**: GitHub lookups are sent in batches that shrink after an error and grow after a success
- **Full Repository Scan**: Hidden commits are scanned together with the normal history of the repository

## Configuration

This source can only be run from the CLI. `pkg/config/config.go` has no case for it, so a YAML `--config` file cannot be used. Git must be installed.

### Authentication

A GitHub token is required, even for public repositories. Every lookup is a GitHub GraphQL API request, and those always need a token.

**CLI Usage:**
```bash
trufflehog github-experimental --repo https://github.com/my-org/my-repo.git --object-discovery --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The token can also be set with the `GITHUB_TOKEN` environment variable instead of `--token`.

### Options

| Flag | Description |
|------|-------------|
| `--repo` | Required. The repository to scan, as a full URL like `https://github.com/my-org/my-repo.git`, or as `my-org/my-repo` |
| `--object-discovery` | Runs the object discovery sub-module. At least one sub-module must be turned on, and today this is the only one |
| `--collision-threshold` | How many short SHA collisions to accept. Default `1`. A higher value means shorter short SHAs and a faster run, but hidden commits can be missed |
| `--delete-cached-data` | Deletes the cached results after the scan |

Only repositories on github.com are supported. GitHub Enterprise Server, GitHub Enterprise Cloud with data residency, and gists are not.

## How Scanning Works

### Scanning Process

1. **Repository Metadata**: Fetches the repository and its fork count from the GitHub API
2. **Clone**: Clones the repository into a temporary folder and lists the objects it already has
3. **Plan**: Estimates how many commits exist across the fork network, and picks the shortest short SHA length, from 4 to 6 characters, that keeps the expected number of collisions under the collision threshold
4. **Resume**: Reads the results of earlier runs from `~/.trufflehog/<owner>/<repo>/`, and leaves out short SHAs already known
5. **Lookup**: Asks GitHub about every remaining short SHA in batches. Found commits are written to `valid_hidden.txt` and the rest to `invalid.txt` in the cache folder after every batch
6. **Fetch**: Fetches every hidden commit into the clone and checks each one out as a branch named `_<commit hash>`, so the scan picks it up
7. **Scan**: Scans the whole clone the same way the git source does
8. **Cleanup**: Deletes the temporary clone. With `--delete-cached-data`, also deletes the cache folder

### Retries and Rate Limits

- A failed batch is retried right away with a smaller batch size.
- When GitHub reports its secondary rate limit, the scan waits 60 seconds before retrying.
- After 10 failed batches in a row, the scan stops with an error. This happens with a bad token or when the primary rate limit is used up. Results found so far stay in the cache folder, so running the scan again continues from there.

### What Gets Scanned

- Every commit a normal clone of the repository gets
- Hidden commits found by object discovery

### What Doesn't Get Scanned

- Hidden commits whose short SHA collides with another commit
- In very large repositories, hidden commits that would need a short SHA longer than 6 characters to tell apart
- Issues, pull requests, comments, wikis, and gists. Use the GitHub source for those

### Run Time

The number of GitHub requests grows quickly with the short SHA length. A 4 character short SHA means about 65 thousand lookups, a 5 character one about 1 million, and a 6 character one about 16 million, sent a few hundred per request. A large repository can take hours. The progress bar on stderr shows how far the lookups have gone.

## Usage Examples

### Scanning a Repository for Hidden Commits

```bash
trufflehog github-experimental --repo https://github.com/my-org/my-repo.git --object-discovery --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Faster Scan With More Collisions Accepted

```bash
trufflehog github-experimental --repo my-org/my-repo --object-discovery --collision-threshold 100 --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning and Deleting the Cache Afterwards

```bash
trufflehog github-experimental --repo my-org/my-repo --object-discovery --delete-cached-data --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Debug Logs

With debug on for this source, the scan logs:

- `V(1)`: `GitHub Experimental source initialized` with the config choices (never the token or the repository URL).
- `V(2)`: `Planned commit guessing` with the object count, fork count, estimated used keys, short SHA length, estimated collisions, cached results, number of candidates and the cache folder. Then `Scanning repo` with the number of hidden commits, `Finished scanning repo` with its duration, and `Deleted cached data`.
- `V(3)`: `Cloning repo`, `Cloned repo` with the object count, `Checked commit batch` for every batch with how many hidden commits it found and how many short SHAs remain, and `Fetching hidden commits`.
- `V(4)`: `Commit check failed, retrying` with the batch sizes, the failures in a row and the error, and `Hit secondary rate limit, waiting`.
- `V(5)`: `GitHub GraphQL request` for every lookup request, with its status and duration.

Every line carries `repo` once the repository is known. Lines from cloning and scanning come from the git source and carry it too. A failure to write the cache is logged as an error at the default level. Other failures end the scan with an error.

## Troubleshooting

### Common Issues

**Issue**: `at least one experimental submodule must be enabled`
**Solution**: Add `--object-discovery`.

---

**Issue**: `token is required for github experimental`
**Solution**: Pass `--token`, or set `GITHUB_TOKEN`.

---

**Issue**: `giving up after 10 failed commit checks in a row: Bad credentials (GitHub Request Error)`
**Solution**: The token is wrong or expired. Use a valid token.

---

**Issue**: `giving up after 10 failed commit checks in a row: API rate limit exceeded ...`
**Solution**: The token's hourly limit is used up. Wait for it to reset and run the same command again. The scan continues from the cached results.

---

**Issue**: The scan takes hours
**Solution**: This is expected for large repositories. Raise `--collision-threshold` for a shorter short SHA and fewer requests, at the cost of possibly missing hidden commits. A stopped run can be continued.

---

**Issue**: Results from an old run are reused
**Solution**: Results are cached in `~/.trufflehog/<owner>/<repo>/`. Delete that folder, or run with `--delete-cached-data`, to start over.
