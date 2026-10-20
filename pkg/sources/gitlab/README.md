# GitLab Source

## Overview

The GitLab source lets TruffleHog scan GitLab projects for secrets, credentials, and sensitive data. It uses the GitLab API to find projects, then clones and scans each one with the git source underneath.

## GitLab Fundamentals

### What does this source scan?

This source finds projects through the GitLab API (by an explicit list, by group, or by listing everything the account can see), then clones and scans each project the same way the git source does.

### Key GitLab Terminology

| Term | Description |
|------|-------------|
| **Project** | A single GitLab repository, called a project in GitLab's own terms |
| **Group** | A GitLab container that holds projects and can also hold subgroups |
| **Subgroup** | A group nested inside another group |
| **Personal Access Token** | A credential tied to a GitLab account, used instead of a username and password |
| **GitLab Cloud** | GitLab's own hosted service at gitlab.com |
| **Self Managed GitLab** | A GitLab instance hosted by the customer on their own infrastructure |

## Features

- **Multiple Authentication Methods**: Personal access token, OAuth refresh token, or username and password
- **Multiple Scan Targets**: Scan by an explicit list of projects, by group, or every project the account can see
- **Project Filtering**: Include or exclude projects using glob patterns
- **Self Managed Support**: Works with self managed GitLab instances in addition to gitlab.com
- **Concurrent Processing**: Projects are cloned and scanned in parallel

## Configuration

### Authentication Methods

#### 1. Personal Access Token

**CLI Usage:**
```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitLab
    token: "glpat-xxxxxxxxxxxxxxxxxxxx"
  name: gitlab-scan
  type: SOURCE_TYPE_GITLAB
  verify: true
```

On the CLI, the token can also be set with the `GITLAB_TOKEN` environment variable instead of `--token`. This does not apply to a YAML config file, since TruffleHog does not read environment variables while loading YAML. A token is always required, there is no unauthenticated scanning mode for GitLab.

---

#### 2. OAuth Refresh Token

This method is only available in the YAML config, not the CLI. Only the refresh token is used to authenticate, the other OAuth fields are not read by this source.

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitLab
    oauth:
      refresh_token: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  name: gitlab-scan
  type: SOURCE_TYPE_GITLAB
  verify: true
```

---

#### 3. Username and Password

This method is only available in the YAML config, not the CLI. If the password is actually a personal access token rather than a real password, TruffleHog notices basic authentication fails and falls back to using it as a token instead.

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitLab
    basic_auth:
      username: my-username
      password: my-password
  name: gitlab-scan
  type: SOURCE_TYPE_GITLAB
  verify: true
```

### Choosing What to Scan

**Scan Specific Projects**

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --repo https://gitlab.com/my-org/my-project
```

`--repo` can be repeated. When projects are given directly, group and project filters are not used, and the include and exclude patterns are ignored for them.

**Scan a Group**

Scans every project in the group and its subgroups.

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --group-id 12345678
```

`--group-id` can be repeated to scan more than one group. It cannot be combined with `--repo`.

**Scan Everything the Account Can See**

If neither `--repo` nor `--group-id` is given, TruffleHog lists every project the token, OAuth account, or username and password can access.

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx
```

On gitlab.com, this only lists projects the account is a member of. On a self managed instance, it lists every project the account can see, not just ones it is a member of.

### Filtering What Gets Scanned

**Include or Exclude Projects**

Only applies when scanning a group or everything the account can see, not to an explicit `--repo` list. A project can be filtered out by either pattern; there is no include-wins rule here, being excluded always wins.

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --include-repos "my-org/prod-*"
```

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --exclude-repos "my-org/test-*"
```

**Include or Exclude Files**

Both flags take a path to a file that holds one regex per line. Blank lines and lines starting with `#` are ignored.

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --include-paths include-patterns.txt
```

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --exclude-paths exclude-patterns.txt
```

**Number of Workers**

There is no way to configure this for GitLab. TruffleHog's global `--concurrency` flag is not used by this source, projects are always cloned and scanned in parallel across as many workers as the machine has CPU cores.

### Clone Location and Cleanup

By default, each project is cloned into a temporary directory and deleted after scanning. `--clone-path` clones into a given directory instead, and `--no-cleanup` (only valid together with `--clone-path`) keeps the clones on disk afterward instead of deleting them.

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --clone-path /path/to/clones --no-cleanup
```

### Self Managed GitLab

Point at a self managed GitLab instance instead of gitlab.com. Only `https` is accepted.

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --endpoint https://gitlab.mycompany.com
```

## How Scanning Works

### Scanning Process

1. **Enumeration**: Depending on the scan target, lists the explicit projects given, every project in the given groups and their subgroups, or every project the account can see, applying the include and exclude filters when listing by group or by account
2. **Project Cloning**: Clones each enumerated project using the git source, the same way the git source scans a remote repository
3. **Commit Scanning**: Scans every commit in the clone for secrets, the same way the git source does
4. **Progress Tracking**: Keeps track of which projects have already been scanned, so a scan can be resumed without redoing work

### What Gets Scanned

- Every commit in every project matching the scan target and filters
- Projects shared into a scanned group from elsewhere, when scanning with `--group-id`. This is always on for a group scan; the YAML `exclude_projects_shared_into_groups` field exists but has no effect under TruffleHog's default GitLab enumeration mode

### What Doesn't Get Scanned

- Projects excluded by `--include-repos` or `--exclude-repos`, when scanning a group or the whole account
- Projects TruffleHog does not have access to with the configured credentials

## Usage Examples

### Scanning Everything the Account Can See

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx
```

### Scanning Specific Projects

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --repo https://gitlab.com/my-org/project-one --repo https://gitlab.com/my-org/project-two
```

### Scanning a Group

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --group-id 12345678
```

### Scanning Self Managed GitLab

```bash
trufflehog gitlab --token glpat-xxxxxxxxxxxxxxxxxxxx --endpoint https://gitlab.mycompany.com
```

## Troubleshooting

### Common Issues

**Issue**: Authentication failures when connecting to GitLab
**Solution**: Check that the token, OAuth refresh token, or username and password are correct and have permission to read the target projects.

---

**Issue**: `invalid config: you cannot specify both repositories and groups at the same time`
**Solution**: Use either `--repo` or `--group-id`, not both together.

---

**Issue**: `https was not used as URL scheme, but is required. Please use https`
**Solution**: A self managed `--endpoint` must use `https`, `http` is rejected.

---

**Issue**: `received error on listing projects, you might not have permissions to do that`
**Solution**: The account used to authenticate does not have permission to list projects this way. Use `--repo` with explicit project URLs instead.

---

**Issue**: No projects found when scanning by group or by account
**Solution**: Check the include and exclude patterns are not excluding every project, and that the token's account actually has access to the expected projects.
