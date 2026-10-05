# Jenkins Source

## Overview

The Jenkins source lets TruffleHog scan the console output of Jenkins build logs for secrets, credentials, and sensitive data. It walks a Jenkins instance's jobs and folders through the Jenkins API, then downloads and scans the build log of every build it finds.

## Jenkins Fundamentals

### What does this source scan?

This source asks the Jenkins API for the list of jobs and folders at a given Jenkins URL, walks into folders recursively, and for every job it finds, downloads the plain text console output of every build and scans it.

### Key Jenkins Terminology

| Term | Description |
|------|-------------|
| **Job** | A single configured build task in Jenkins, such as a Freestyle project or a Pipeline |
| **Folder** | A container that groups jobs and can hold other folders |
| **Build** | One run of a job, numbered in order |
| **Console Output** | The full text log produced while a build ran, available as a plain text page |

## Features

- **Folder Traversal**: Recursively walks Jenkins folders to find every job underneath them
- **Multiple Authentication Methods**: Username and password, a custom header, or unauthenticated
- **Self Signed Certificate Support**: Can skip TLS certificate verification for instances using one

## Configuration

### Authentication Methods

#### 1. Username and Password

**CLI Usage:**
```bash
trufflehog jenkins --url https://jenkins.example.com --username my-username --password my-password
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Jenkins
    endpoint: https://jenkins.example.com
    basic_auth:
      username: my-username
      password: my-password
  name: jenkins-scan
  type: SOURCE_TYPE_JENKINS
  verify: true
```

On the CLI, the URL, username, and password can also be set with the `JENKINS_URL`, `JENKINS_USERNAME`, and `JENKINS_PASSWORD` environment variables instead of the matching flags. This does not apply to a YAML config file, since TruffleHog does not read environment variables while loading YAML.

---

#### 2. Custom Header

Sends a fixed header, such as an API token header, with every request. This method is only available in the YAML config, not the CLI.

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Jenkins
    endpoint: https://jenkins.example.com
    header:
      key: "Authorization"
      value: "Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  name: jenkins-scan
  type: SOURCE_TYPE_JENKINS
  verify: true
```

---

#### 3. Unauthenticated

**CLI Usage:**

Leave out `--username` and `--password` to scan without authentication. This is also what happens if only one of the two is given, since the CLI only uses basic auth when both are set together.

```bash
trufflehog jenkins --url https://jenkins.example.com
```

**YAML Configuration:**

In the YAML config, this must be set explicitly. Leaving out the credential entirely is rejected.

```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Jenkins
    endpoint: https://jenkins.example.com
    unauthenticated: {}
  name: jenkins-scan
  type: SOURCE_TYPE_JENKINS
  verify: true
```

### Self Signed Certificates

```bash
trufflehog jenkins --url https://jenkins.example.com --username my-username --password my-password --insecure-skip-verify-tls
```

On the CLI, this can also be set with the `JENKINS_INSECURE_SKIP_VERIFY_TLS` environment variable.

## How Scanning Works

### Scanning Process

1. **Job Listing**: Asks the Jenkins API for the jobs directly under the given URL
2. **Folder Traversal**: For every folder found, repeats the job listing inside that folder, continuing until every nested folder has been walked
3. **Build Listing**: For every job that is a Freestyle project or a Pipeline, lists all of its builds
4. **Build Log Scanning**: Downloads the console output of every build and scans its text for secrets
5. **Progress Tracking**: Reports progress as each job is processed, so a scan can be monitored while it runs

### What Gets Scanned

- The console output of every build of every Freestyle project and Pipeline job found underneath the given URL, including jobs inside nested folders

### What Doesn't Get Scanned

- Job types other than a Freestyle project or a Pipeline, such as a Multi-configuration project (in the Jenkins API this is the `hudson.matrix.MatrixProject` class)
- Anything whose Jenkins API class is not recognized as a plain folder or as one of the two scannable job types, including any job container that is not the plain Jenkins folder type
- Anything outside the build's console output, such as artifacts, build parameters, or job configuration

There is no concurrency for this source: jobs, builds, and their console output are all fetched and scanned one at a time, and there is no flag to change that.

## Usage Examples

### Scanning with Username and Password

```bash
trufflehog jenkins --url https://jenkins.example.com --username my-username --password my-password
```

### Scanning Without Authentication

```bash
trufflehog jenkins --url https://jenkins.example.com
```

### Scanning an Instance with a Self Signed Certificate

```bash
trufflehog jenkins --url https://jenkins.example.com --username my-username --password my-password --insecure-skip-verify-tls
```

## Troubleshooting

### Common Issues

**Issue**: Authentication failures when connecting to Jenkins
**Solution**: Check that the username and password, or the custom header, are correct and have permission to read the target jobs and builds.

---

**Issue**: A username was given but the scan still ran unauthenticated
**Solution**: On the CLI, both `--username` and `--password` must be set together for basic authentication to be used. If either one is missing, the scan falls back to unauthenticated without an error.

---

**Issue**: `Received non-200 status from get jenkins jobs request`
**Solution**: Check the Jenkins URL is correct and reachable, and that the credentials have permission to list jobs at that URL.

---

**Issue**: Certificate errors when connecting to a self managed Jenkins instance
**Solution**: Pass `--insecure-skip-verify-tls` if the instance uses a self signed certificate.

---

**Issue**: Some jobs are missing from the scan
**Solution**: TruffleHog only scans Freestyle projects and Pipeline jobs, and only recurses into the plain Jenkins folder type. A job of another type, or one nested inside a different kind of container, is silently skipped.
