# Git Source

## Overview

The Git source lets TruffleHog scan Git repositories for secrets, credentials, and sensitive data. It reads the full commit history of a repository, not just the files as they look today, so secrets that were committed once and later removed are still found.

## Git Fundamentals

### What does this source scan?

A Git repository keeps every version of every file it has ever tracked. A secret that was committed and then deleted in a later commit still lives in the history. This source walks that history commit by commit and scans what changed in each one.

### Key Git Terminology

| Term | Description |
|------|-------------|
| **Commit** | A saved snapshot of changes, identified by a 40 character hash |
| **Diff** | The lines that changed in a file between one commit and the one before it |
| **Branch** | A named pointer to a commit, such as `main` |
| **Ref** | Any named pointer to a commit, which covers branches, tags, and remote tracking names |
| **Clone** | A local copy of a remote repository |
| **Bare repository** | A repository with no working copy of the files, holding only the Git data itself |
| **Mirror clone** | A bare clone that copies every ref from the remote, not only the default branch |
| **Staged changes** | Changes added with `git add` but not committed yet |
| **Merge base** | The commit where two branches last shared history |

## Features

- **Full History Scanning**: Walks every commit reachable from every ref, so deleted secrets are still found
- **Commit Metadata Scanning**: Scans the author email, committer, and commit message, not only file changes
- **Multiple Sources**: Scan a remote URL over HTTPS or SSH, or a repository already on disk
- **Multiple Authentication Methods**: Unauthenticated, username and password or token, or SSH
- **Scan Range Control**: Limit the scan to one branch, to commits after a given commit, or to a maximum number of commits
- **Path Filtering**: Include or exclude files by regex, or exclude them by glob at the `git log` level
- **Staged Change Scanning**: Scans changes that are staged but not committed yet, which makes pre commit hook use possible
- **Binary File Handling**: Reads binary files in full through `git cat-file` instead of reading the diff, or skips them
- **Clone Retries**: Retries a failed clone when the failure looks like a network problem or a rate limit

## Requirements

The `git` command must be installed and on your `PATH`. The version must be 2.20.0 or newer, and below 3.0.0. TruffleHog checks this when the source starts and fails with a clear message if it is not met.

## Configuration

### Repository Location

The CLI takes the repository as a positional argument, not a flag. The URL must have a scheme, since a plain path like `/home/user/repo` is rejected as an unsupported URI:

```bash
# HTTPS (http is accepted the same way)
trufflehog git https://github.com/trufflesecurity/test_keys.git

# SSH
trufflehog git ssh://git@github.com/trufflesecurity/test_keys.git

# A repository already on disk
trufflehog git file:///path/to/local/repo
```

A remote repository is cloned first, then scanned. A `file://` path is also cloned into a separate directory, so the original copy is never written to.

In the YAML config, use `repositories` for remote URLs to clone, and `directories` for repositories already on disk, which are scanned where they are.

### Authentication Methods

#### 1. Unauthenticated

For public repositories.

**CLI Usage:**
```bash
trufflehog git https://github.com/trufflesecurity/test_keys.git
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Git
    unauthenticated: {}
    repositories:
    - https://github.com/trufflesecurity/test_keys.git
  name: git-scan
  type: SOURCE_TYPE_GIT
  verify: true
```

---

#### 2. Basic Authentication

For private repositories that need a username and a password or token.

**CLI Usage:**

There is no separate flag for this. Put the credentials in the URL:

```bash
trufflehog git https://myuser:mytoken@github.com/myorg/private-repo.git
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Git
    basic_auth:
      username: myuser
      password: mytoken
    repositories:
    - https://github.com/myorg/private-repo.git
  name: git-scan
  type: SOURCE_TYPE_GIT
  verify: true
```

---

#### 3. SSH

Uses the SSH keys already set up on the machine. There is no key or passphrase field to fill in.

**CLI Usage:**
```bash
trufflehog git ssh://git@github.com/myorg/private-repo.git
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Git
    ssh_auth: {}
    repositories:
    - ssh://git@github.com/myorg/private-repo.git
  name: git-scan
  type: SOURCE_TYPE_GIT
  verify: true
```

### Limiting the Scan Range

**Scanning One Branch**

By default every ref in the repository is scanned. Pass a branch name to scan only that branch.

```bash
trufflehog git https://github.com/myorg/myrepo.git --branch main
```

**Scanning Since a Commit**

Scan only the commits made after the given commit. If the repository is on `github.com`, TruffleHog looks up the date of that commit through the GitHub API and does a shallow clone from that date, which makes the clone much smaller. For any other host it falls back to a normal clone and stops walking once it reaches that commit.

```bash
trufflehog git https://github.com/myorg/myrepo.git --since-commit a1b2c3d4
```

If a `GITHUB_TOKEN` environment variable is set, it is used for that commit lookup, which is needed for private repositories.

**Limiting Commit Depth**

Stop after this many commits.

```bash
trufflehog git https://github.com/myorg/myrepo.git --max-depth 100
```

### Filtering What Gets Scanned

**Include or Exclude Paths**

Both flags take a path to a file that holds one regex per line. Blank lines and lines starting with `#` are ignored, so the file can hold comments.

```bash
trufflehog git https://github.com/myorg/myrepo.git --include-paths ./include.txt
```

```bash
trufflehog git https://github.com/myorg/myrepo.git --exclude-paths ./exclude.txt
```

**Exclude Globs**

Takes a comma separated list of globs. This filter is applied at the `git log` level, so the excluded files are never read at all, which makes the scan faster than filtering afterwards.

```bash
trufflehog git https://github.com/myorg/myrepo.git --exclude-globs "*.min.js,vendor/*"
```

### Clone Location and Cleanup

By default a repository is cloned into a temporary directory and that directory is deleted after the scan. Use `--clone-path` to clone somewhere else, and `--no-cleanup` to keep the clone afterwards.

```bash
trufflehog git https://github.com/myorg/myrepo.git --clone-path /tmp/my-clones --no-cleanup
```

`--no-cleanup` only works together with `--clone-path`, and the path given to `--clone-path` must already exist and be a directory. Each clone gets its own directory inside it, so disk use grows with every repository and every run.

Warning: cleanup deletes the directory that was scanned, and it is keyed on `--clone-path` being set rather than on whether that directory was actually cloned by TruffleHog. So when `--clone-path` is set and `--no-cleanup` is not, a repository that was scanned in place gets deleted too. That applies to `--trust-local-git-config` on the CLI, and to `directories` entries in the YAML config. Do not combine either of those with `--clone-path` or `clone_path`.

### Other Options

**Bare Repository**

Scan a repository that has no working copy, which is useful in a pre receive hook.

```bash
trufflehog git file:///path/to/repo.git --bare
```

**Trust Local Git Config**

For a `file://` path, scan the repository where it already is instead of cloning it first. This makes TruffleHog read the local Git config of that repository.

```bash
trufflehog git file:///path/to/local/repo --trust-local-git-config
```

Do not pass `--clone-path` alongside this flag, for the reason given in the cleanup warning above.

## How Scanning Works

### Scanning Process

1. **Git Check**: Confirms the `git` command is installed and its version is supported.
2. **Clone or Open**: A remote URL is cloned into a temporary directory or into `--clone-path`. A repository already on disk is opened where it is.
3. **Commit Walk**: Runs `git log` over the repository with full history, across every ref by default, or over one branch when `--branch` is given.
4. **Commit Metadata Chunk**: For each commit, the author email, the committer, and the commit message are sent to the detection engine as their own chunk.
5. **File Diff Chunks**: For each changed file in the commit, the diff is sent as a chunk tagged with the commit hash, file name, author email, timestamp, repository, and line number. A diff larger than the chunk size is split into several chunks line by line.
6. **Binary Files**: A binary file is not read from the diff. Its full contents are pulled with `git cat-file` and passed through the file handlers, which also unpack archives.
7. **Staged Changes**: If the repository is not bare, `git diff --cached` is scanned as well, so changes staged but not committed are covered.
8. **Cleanup**: The clone is deleted unless `--no-cleanup` was used with `--clone-path`.

### Clone Retries

A clone that fails because of a network problem or what looks like a rate limit is retried, up to 3 attempts in total, each from a fresh directory. Network failures wait 5 seconds times the attempt number, and rate limit failures wait 60 seconds times the attempt number, since those take longer to clear. Any other failure, such as a bad password or a missing repository, is returned right away without retrying.

### What Gets Scanned

- The diff of every added or modified file in every commit. When `--since-commit` is used, deletions and renames are included as well
- Commit metadata: author email, committer, and commit message
- Binary files, read in full rather than as a diff
- Files inside archives found in the repository
- Staged changes, when the repository is not bare

### What Doesn't Get Scanned

- Files excluded by the include paths, exclude paths, or exclude globs filters
- Commits past `--max-depth`, or older than the commit given to `--since-commit`
- Refs other than the one named by `--branch`, when that flag is used
- Binary files, when `--force-skip-binaries` is used
- Binary files whose extension TruffleHog already skips, such as common image, audio, video, and font types
- Files inside archives, when `--force-skip-archives` is used
- Staged changes in a bare repository, since a bare repository has nothing staged

## Usage Examples

### Scanning a Public Repository

```bash
trufflehog git https://github.com/trufflesecurity/test_keys.git
```

### Scanning a Local Repository

```bash
trufflehog git file:///path/to/local/repo
```

### Scanning One Branch Only

```bash
trufflehog git https://github.com/myorg/myrepo.git --branch main
```

### Scanning Only Recent History

```bash
trufflehog git https://github.com/myorg/myrepo.git --max-depth 50
```

### Scanning a Private Repository Over SSH

```bash
trufflehog git ssh://git@github.com/myorg/private-repo.git
```

### Keeping the Clone After the Scan

```bash
trufflehog git https://github.com/myorg/myrepo.git --clone-path /tmp/my-clones --no-cleanup
```

## Pre Commit Hook Use

TruffleHog notices when it is being run as a pre commit hook and changes some settings on its own:

- Local Git config is trusted
- Only staged changes are scanned
- Only verified and unknown results are shown
- The run fails if anything is found, which stops the commit

It detects this from these environment variables:

| Variable | Set by |
|----------|--------|
| `PRE_COMMIT=1` | The pre-commit framework |
| `HUSKY=1` | Husky, modern versions |
| `HUSKY_GIT_PARAMS` | Husky, versions below 4.0 |
| `TRUFFLEHOG_PRE_COMMIT=1` | Set by hand in a plain Git hook script |

For a plain Git hook with no framework, export the variable yourself in `.git/hooks/pre-commit`:

```bash
export TRUFFLEHOG_PRE_COMMIT=1
```

## Troubleshooting

### Common Issues

**Issue**: `'git' command not found in $PATH`
**Solution**: Install Git and make sure it is on your `PATH`. The version must be 2.20.0 or newer and below 3.0.0.

---

**Issue**: Authentication failures when cloning a private repository
**Solution**: For HTTPS, check the username and token in the URL or in the config, and that the token can read the repository. For SSH, check that the key on the machine is loaded and accepted by the host.

---

**Issue**: `--no-cleanup can only be used together with --clone-path`
**Solution**: `--no-cleanup` keeps the clone in place, so a path to keep it in is needed. Pass `--clone-path` as well, pointing at a directory that already exists.

---

**Issue**: Running out of disk space during a scan
**Solution**: Every repository is cloned in full, so a large history needs a lot of space. Drop `--no-cleanup` so clones are deleted after each scan, or use `--since-commit` on a `github.com` repository so the clone is shallow.

---

**Issue**: The scan is slow on a large repository
**Solution**: Narrow it with `--branch`, `--max-depth`, or `--since-commit`. Use `--exclude-globs` rather than `--exclude-paths`, since globs are filtered inside `git log` and those files are never read.

---

**Issue**: Clones keep failing on a host that rate limits
**Solution**: TruffleHog already retries a rate limited clone 3 times, waiting longer between each try. If it still fails, wait and scan fewer repositories at once.
