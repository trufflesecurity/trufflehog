# HuggingFace Source

## Overview

The HuggingFace source lets TruffleHog scan HuggingFace models, spaces, datasets, and buckets for secrets, credentials, and sensitive data. It uses the HuggingFace API to find repositories, then clones and scans each one with the git source underneath. Buckets are handled differently since they are plain file storage, not git repositories.

## HuggingFace Fundamentals

### What does this source scan?

This source finds models, spaces, and datasets through the HuggingFace API (by an explicit list, or by organization and user), then clones and scans each one the same way the git source does. Buckets are found the same way but are downloaded and scanned file by file instead of being cloned, since they are not git repositories.

### Key HuggingFace Terminology

| Term | Description |
|------|-------------|
| **Model** | A trained machine learning model hosted on HuggingFace, stored as a git repository |
| **Space** | An application or demo hosted on HuggingFace, stored as a git repository |
| **Dataset** | A collection of data hosted on HuggingFace, stored as a git repository |
| **Bucket** | Plain object storage hosted on HuggingFace, not a git repository |
| **Organization** | A HuggingFace account that holds models, spaces, datasets, and buckets owned by a team |
| **Discussion** | A conversation thread attached to a model, space, or dataset |

## Features

- **Multiple Scan Targets**: Scan models, spaces, datasets, and buckets, by an explicit list or by organization and user
- **Multiple Authentication Methods**: Personal access token, or unauthenticated for public repositories
- **Repository Filtering**: Include or exclude models, spaces, datasets, and buckets using glob patterns, or skip an entire resource type
- **Discussion and Pull Request Scanning**: Optionally scan the comments on discussions and pull requests
- **Concurrent Processing**: Repositories and bucket files are cloned, downloaded, and scanned in parallel across a configurable number of workers

## Configuration

Note: as of this writing, `pkg/config/config.go` does not have a case for `SOURCE_TYPE_HUGGINGFACE` in its source loader, so a YAML `--config` file cannot be used for HuggingFace. Use the CLI flags or environment variable below instead.

### Authentication Methods

#### 1. Personal Access Token

**CLI Usage:**
```bash
trufflehog huggingface --org my-org --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The token can also be set with the `HUGGINGFACE_TOKEN` environment variable instead of `--token`.

---

#### 2. Unauthenticated

Only works for public models, spaces, datasets, and buckets.

**CLI Usage:**
```bash
trufflehog huggingface --org my-org
```

### Choosing What to Scan

At least one of `--org`, `--user`, `--model`, `--space`, `--dataset`, or `--bucket` must be given.

**Scan an Organization or User**

```bash
trufflehog huggingface --org my-org --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```bash
trufflehog huggingface --user my-user --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

This finds every model, space, dataset, and bucket owned by the organization or user. Use `--skip-all-models`, `--skip-all-spaces`, `--skip-all-datasets`, or `--skip-all-buckets` to leave out a whole resource type.

```bash
trufflehog huggingface --org my-org --skip-all-buckets --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Scan Specific Models, Spaces, Datasets, or Buckets**

```bash
trufflehog huggingface --model my-org/my-model --space my-org/my-space --dataset my-org/my-dataset --bucket my-org/my-bucket --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Each of these flags can be repeated, and each name should be in `owner/name` form so TruffleHog can build the right URL for it. Unlike `--include-*` and `--ignore-*`, TruffleHog does not check this format for `--model`, `--space`, `--dataset`, or `--bucket` themselves, a name without a slash just produces a broken URL later instead of a clear error. When a model, space, dataset, or bucket is given directly this way, `--include-*` and `--ignore-*` filters are not applied to it.

### Filtering What Gets Scanned

**Include or Exclude Models, Spaces, Datasets, or Buckets**

These only apply when scanning with `--org` or `--user`, not to resources given directly with `--model`, `--space`, `--dataset`, or `--bucket`. Each name must be in `owner/name` form, and can also be a glob pattern.

```bash
trufflehog huggingface --org my-org --include-models "my-org/prod-*" --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```bash
trufflehog huggingface --org my-org --ignore-datasets "my-org/test-*" --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The same pattern works for `--include-spaces`, `--ignore-spaces`, `--include-buckets`, and `--ignore-buckets`.

**Number of Workers**

There is no HuggingFace specific flag for this. Use TruffleHog's global `--concurrency` flag to set how many repositories and bucket files are processed at the same time.

```bash
trufflehog huggingface --org my-org --concurrency 10 --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning Discussions and Pull Requests

```bash
trufflehog huggingface --org my-org --include-discussions --include-prs --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Only the comments on a discussion or pull request are scanned, there is no separate description text to scan.

### Self Hosted Endpoint

```bash
trufflehog huggingface --org my-org --endpoint https://huggingface.mycompany.com --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## How Scanning Works

### Scanning Process

1. **Enumeration**: Lists models, spaces, datasets, and buckets from the given organizations and users, applying the include and exclude filters, then adds any models, spaces, datasets, and buckets given directly
2. **Model, Space, and Dataset Cloning**: Clones each one using the git source, the same way the git source scans a remote repository
3. **Commit Scanning**: Scans every commit in the clone for secrets, the same way the git source does, then deletes the clone
4. **Bucket File Listing**: For each bucket, lists its files, skipping anything larger than 250MB
5. **Bucket File Scanning**: Downloads each remaining bucket file and scans its contents directly, without cloning
6. **Discussion Scanning**: If `--include-discussions` or `--include-prs` is set, fetches discussions and pull requests for each model, space, and dataset and scans their comments
7. **Progress Tracking**: Keeps track of which models, spaces, and datasets have already been scanned, so a scan can be resumed without redoing work

### What Gets Scanned

- Every commit in every model, space, and dataset matching the scan target and filters
- Files in every bucket matching the scan target and filters, up to 250MB in size
- Comments on discussions and pull requests, when `--include-discussions` or `--include-prs` is set

### What Doesn't Get Scanned

- An entire resource type, when its `--skip-all-*` flag is set
- Models, spaces, datasets, or buckets excluded by an `--include-*` or `--ignore-*` filter, for an organization or user scan
- Bucket files larger than 250MB
- Discussion and pull request descriptions, only their comments are scanned

## Usage Examples

### Scanning an Organization

```bash
trufflehog huggingface --org my-org --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning a Specific Model

```bash
trufflehog huggingface --model my-org/my-model --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning an Organization's Datasets Only

```bash
trufflehog huggingface --org my-org --skip-all-models --skip-all-spaces --skip-all-buckets --token hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning a Public Model Without Authentication

```bash
trufflehog huggingface --model my-org/public-model
```

## Troubleshooting

### Common Issues

**Issue**: `invalid config: you must specify at least one organization, user, model, space, dataset or bucket`
**Solution**: Pass at least one of `--org`, `--user`, `--model`, `--space`, `--dataset`, or `--bucket`.

---

**Issue**: `invalid owner/repo: <name>`
**Solution**: A value passed to `--include-models`, `--ignore-models`, or any of the other include and ignore flags is not in `owner/name` form. TruffleHog checks this for the include and ignore flags only, not for `--model`, `--space`, `--dataset`, or `--bucket` themselves.

---

**Issue**: `invalid API key`
**Solution**: Check that the token is correct. This also appears if a token is required but was left out.

---

**Issue**: `access to this repo is restricted and you are not in the authorized list`
**Solution**: The authenticated account, or an unauthenticated request, does not have permission to read this model, space, or dataset. Request access on HuggingFace first.
