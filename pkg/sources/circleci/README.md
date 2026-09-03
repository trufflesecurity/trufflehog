# CircleCI Source

## Overview

The CircleCI source enables TruffleHog to scan CircleCI build data for secrets, credentials, and sensitive data. It scans every project accessible by the provided API token, walking each project's build history, job steps, and build configuration.

## CircleCI Fundamentals

### What is CircleCI?

CircleCI is a continuous integration and delivery (CI/CD) platform that automates building, testing, and deploying software. Pipelines are triggered by VCS events (e.g., a GitHub or Bitbucket push) and run a sequence of jobs and steps defined in a project's `config.yml`.

### Key CircleCI Terminology

| Term | Description |
|------|-------------|
| **Project** | A repository connected to CircleCI, identified by VCS type, org/username, and repo name |
| **Build** | A single execution of a project's pipeline, identified by an incrementing build number |
| **Job** | A defined unit of work within a build (e.g., `build`, `test`, `deploy`) |
| **Step** | An individual command or action executed within a job |
| **Action** | The underlying execution unit CircleCI's v1.1 API returns per step, with a link to its output |
| **circle.yml** | The build configuration used for a given build (legacy v1.1 naming for `config.yml`) |
| **API Token** | A personal or project token used to authenticate against the CircleCI API |

## Features

- **Full Project Discovery**: Automatically lists every project visible to the provided token
- **Build History Scanning**: Iterates through all builds for each discovered project
- **Job Step Output Scanning**: Fetches and scans the output of every action within every build step
- **Build Configuration Scanning**: Scans the `circle.yml`/`config.yml` used for each build
- **Concurrent Processing**: Projects are scanned in parallel using a bounded worker pool
- **CIRCLE_SHA1 Redaction**: Strips the `CIRCLE_SHA1=` environment line from scanned output to avoid noisy commit-SHA false positives

## Configuration

### Authentication

CircleCI only supports token-based authentication.

**YAML Configuration:**
```yaml
sources:
  - type: circleci
    name: circleci-scan
    circleci:
      token: "cci_xxxxxxxxxxxxxxxxxxxx"
```

**CLI Usage:**
```bash
trufflehog circleci --token cci_xxxxxxxxxxxxxxxxxxxx
```

The token can also be provided via the `CIRCLECI_TOKEN` environment variable:

```bash
export CIRCLECI_TOKEN=cci_xxxxxxxxxxxxxxxxxxxx
trufflehog circleci
```

## How Scanning Works

### Scanning Process

1. **Project Listing**: Fetches all projects the token can access via `GET /projects`
2. **Build Listing**: For each project, lists all builds via `GET /project/:vcs/:org/:repo`
3. **Job/Step Retrieval**: For each build, fetches step and action details via `GET /project/:vcs/:org/:repo/:build_num`
4. **Action Output Scanning**: Downloads and scans the output of every action's `output_url`
5. **Build Config Scanning**: Scans the build's `circle.yml` content
6. **Chunk Generation**: Emits chunks of data to the detection engine, tagged with VCS type, username, repository, build number, and step name

### What Gets Scanned

- **Job Step Output**: stdout/stderr captured for each executed step
- **Build Configuration**: The `circle.yml`/`config.yml` content used for each build

### What Doesn't Get Scanned

- Artifacts, checkout keys, and environment variables (not currently implemented; see `TODO` in source)
- Lines containing `CIRCLE_SHA1=` (explicitly stripped before scanning)

## Usage Examples

### Scanning All Accessible Projects

```bash
trufflehog circleci --token cci_xxxxxxxxxxxxxxxxxxxx
```

### Scanning Using an Environment Variable Token

```bash
export CIRCLECI_TOKEN=cci_xxxxxxxxxxxxxxxxxxxx
trufflehog circleci
```

## Troubleshooting

### Common Issues

**Issue**: `invalid credentials, status 401` when listing projects
**Solution**: Verify the token is correct and has not been revoked. Regenerate a personal API token from CircleCI account settings if needed.

---

**Issue**: `no builds found for project` errors for some projects
**Solution**: This is expected for projects with no build history; scanning continues for other projects.

---

**Issue**: Slow scanning with many projects
**Solution**: Increase concurrency via the `concurrency` setting used when initializing the source; scanning is parallelized per project.

---

**Issue**: Missing artifacts, checkout keys, or environment variables in scan results
**Solution**: These are not yet scanned by this source (tracked as a `TODO`); only build step output and build configuration are covered today.
