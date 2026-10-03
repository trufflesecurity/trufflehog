# GCS Source

## Overview

The GCS source lets TruffleHog scan files stored in Google Cloud Storage buckets for secrets, credentials, and sensitive data. It lists the buckets in a project, walks the objects inside them, and scans each object's contents.

## GCS Fundamentals

### What is GCS?

Google Cloud Storage (GCS) is Google's object storage service. Files are stored as objects inside buckets, and buckets belong to a Google Cloud project.

### Key GCS Terminology

| Term | Description |
|------|-------------|
| **Project** | A Google Cloud project that owns one or more buckets |
| **Bucket** | A container that holds objects, similar to a top level folder |
| **Object** | A single file stored inside a bucket |
| **Service Account** | A Google Cloud identity used by an application to authenticate, instead of a person |
| **Application Default Credentials (ADC)** | Credentials that Google Cloud client libraries pick up automatically from the environment, such as a service account attached to a VM or Cloud Run service |
| **ACL** | Access Control List. Defines who can read or write an object or bucket |

## Features

- **Multiple Authentication Methods**: Service account file, service account JSON, API key, OAuth, Application Default Credentials, or unauthenticated for public buckets
- **Bucket and Object Filtering**: Scan only specific buckets or objects, or exclude specific ones, using glob patterns
- **Size Limits**: Skips objects larger than a configurable maximum size, so scans do not stall on very large files
- **Concurrent Processing**: Buckets and objects are processed in parallel across a configurable number of workers
- **Resumable Scans**: Tracks which objects have already been scanned so a scan can be resumed without redoing work

## Configuration

### Authentication Methods

#### 1. Application Default Credentials (ADC)

Uses the credentials Google Cloud already provides in the environment, such as a service account attached to a VM.

**CLI Usage:**
```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GCS
    project_id: my-gcp-project
    adc: {}
  name: gcs-scan
  type: SOURCE_TYPE_GCS
  verify: true
```

---

#### 2. Service Account File

**CLI Usage:**
```bash
trufflehog gcs --project-id my-gcp-project --service-account /path/to/service-account.json
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GCS
    project_id: my-gcp-project
    service_account_file: /path/to/service-account.json
  name: gcs-scan
  type: SOURCE_TYPE_GCS
  verify: true
```

---

#### 3. API Key

Can only be used for public buckets.

**CLI Usage:**
```bash
trufflehog gcs --project-id my-gcp-project --api-key AIzaxxxxxxxxxxxxxxxxxxxxxxxx
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GCS
    project_id: my-gcp-project
    api_key: "AIzaxxxxxxxxxxxxxxxxxxxxxxxx"
  name: gcs-scan
  type: SOURCE_TYPE_GCS
  verify: true
```

---

#### 4. JSON Service Account

Same as the service account file method, but the JSON content is passed directly instead of a file path. This method is only available in the YAML config, not the CLI.

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GCS
    project_id: my-gcp-project
    json_service_account: '{"type": "service_account", "project_id": "my-gcp-project", ...}'
  name: gcs-scan
  type: SOURCE_TYPE_GCS
  verify: true
```

---

#### 5. OAuth

Uses an OAuth2 client ID with a refresh token and access token. This method is only available in the YAML config, not the CLI.

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GCS
    project_id: my-gcp-project
    oauth:
      client_id: xxxxxxxxxxxx.apps.googleusercontent.com
      refresh_token: "1//xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      access_token: "ya29.xxxxxxxxxxxxxxxxxxxxxxxx"
  name: gcs-scan
  type: SOURCE_TYPE_GCS
  verify: true
```

---

#### 6. Unauthenticated

Can only be used for public buckets. The project ID is not needed, but the buckets to scan must be listed with `include_buckets`, since the source cannot list all buckets in a project without authentication.

**CLI Usage:**
```bash
trufflehog gcs --without-auth --include-buckets my-public-bucket
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GCS
    unauthenticated: {}
    include_buckets:
    - my-public-bucket
  name: gcs-scan
  type: SOURCE_TYPE_GCS
  verify: true
```

Environment variables are also supported: `GOOGLE_CLOUD_PROJECT` for the project ID, and `GOOGLE_API_KEY` for the API key.

### Filtering What Gets Scanned

**Include or Exclude Buckets**

Only one of include or exclude can be used at a time for buckets. If both are set, include wins.

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment --include-buckets "logs-*"
```

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment --exclude-buckets "temp-*"
```

**Include or Exclude Objects**

Same rule applies, only one of include or exclude can be used at a time for objects. If a bucket is already known, it is faster to also set `include_buckets` alongside `include_objects`.

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment --include-objects "*.env"
```

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment --exclude-objects "*.log"
```

**Maximum Object Size**

Objects larger than this size are skipped. The default is 10MB. Setting it to 0, a negative value, or anything above 50MB resets it back to the 10MB default instead of using the value given.

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment --max-object-size 20MB
```

**Number of Workers**

There is no GCS specific flag for this. Use TruffleHog's global `--concurrency` flag to set how many buckets and objects are processed at the same time. If not set, it defaults to the number of CPU cores available.

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment --concurrency 10
```

## How Scanning Works

### Scanning Process

1. **Enumeration**: Lists every bucket in the project (or uses the buckets given with `include_buckets` when unauthenticated), then counts the objects in each one. This count is used to show scan progress.
2. **Bucket Listing**: Lists the buckets again to start the actual scan, applying the include and exclude filters.
3. **Object Listing**: For each bucket, lists its objects in parallel, applying the include and exclude filters and skipping objects over the size limit.
4. **Object Scanning**: Downloads each object and sends its contents to the detection engine as a chunk, tagged with the bucket name, object name, and other metadata.
5. **Progress Tracking**: Keeps a cache of the MD5 hash of every object already scanned, so if the same scan is resumed later, already scanned objects are skipped.

### What Gets Scanned

- Objects in buckets matching the include and exclude bucket filters
- Objects matching the include and exclude object filters
- Objects at or under the configured maximum object size

### What Doesn't Get Scanned

- Objects excluded by the include or exclude bucket or object filters
- Objects larger than the maximum object size
- Objects with file extensions TruffleHog already knows to skip, such as common image, audio, video, and font file types
- Empty objects, since they have a size of 0

## Usage Examples

### Scanning All Buckets in a Project with ADC

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment
```

### Scanning a Public Bucket Without Authentication

```bash
trufflehog gcs --without-auth --include-buckets my-public-bucket
```

### Scanning Only Specific Buckets

```bash
trufflehog gcs --project-id my-gcp-project --cloud-environment --include-buckets "prod-logs,prod-backups"
```

### Scanning with a Service Account and a Size Limit

```bash
trufflehog gcs --project-id my-gcp-project --service-account /path/to/service-account.json --max-object-size 5MB
```

## Troubleshooting

### Common Issues

**Issue**: Authentication failures when connecting to GCS
**Solution**: Check that the service account, API key, or ADC setup is correct and has permission to read the target buckets. Only one authentication method can be used at a time.

---

**Issue**: `project ID is required` error
**Solution**: A project ID is required for every authentication method except unauthenticated scanning. Pass `--project-id` or set the `GOOGLE_CLOUD_PROJECT` environment variable.

---

**Issue**: No buckets found when scanning without authentication
**Solution**: Unauthenticated scans cannot list buckets in a project. Pass the exact bucket names with `--include-buckets`.

---

**Issue**: Objects are being skipped
**Solution**: Check the object is under the maximum object size, matches the include filter if one is set, and does not match the exclude filter.
