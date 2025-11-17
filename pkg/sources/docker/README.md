# Docker Source

## Overview

The Docker source enables TruffleHog to scan Docker images for secrets, credentials, and sensitive data. It supports scanning images from multiple sources including Docker registries, local Docker daemon, and tarball files.

## Docker Fundamentals

### What is Docker?

Docker is a containerization platform that packages applications and their dependencies into isolated containers. A Docker image is a read-only template used to create containers, consisting of multiple layers stacked on top of each other.

### Key Docker Terminology

| Term | Description |
|------|-------------|
| **Image** | A read-only template containing application code, runtime, libraries, and dependencies |
| **Layer** | Each modification to an image creates a new layer. Layers are stacked and merged to form the final image |
| **Tag** | A label applied to an image (e.g., `latest`, `v1.0.0`) for version identification |
| **Digest** | A SHA256 hash that uniquely identifies an image or layer |
| **Registry** | A repository for storing and distributing Docker images (e.g., Docker Hub, Quay, GHCR) |
| **Daemon** | The Docker service running on the host that manages containers and images |
| **Tarball** | A compressed archive file containing an exported Docker image |
| **History** | Metadata about how an image was built, including commands executed |

## Features

- **Multiple Image Sources**: Scan images from remote registries, local Docker daemon, or tarball files
- **Layer-by-Layer Scanning**: Examines each layer independently for comprehensive coverage
- **History Metadata Scanning**: Analyzes image build history for exposed secrets in commands
- **Concurrent Processing**: Parallel layer scanning for improved performance
- **Authentication Support**: Multiple authentication methods for private registries
- **File Exclusion**: Configure patterns to skip specific files or directories
- **Size Limits**: Automatically skips files exceeding 50MB to optimize performance
- **Scan All Images Under a Namespace**: Enables automatic discovery and scanning of all container images under a specified namespace (organization or user) in supported registries such as Docker Hub, Quay, and GHCR. Users no longer need to manually list or specify individual image names. The system retrieves all public images within the namespace, and if a valid registry token is provided includes private images as well. This allows for large-scale, automated scanning across all repositories within an organization.

## Configuration

### Connection Types

The Docker source supports several image reference formats:

```text
// Remote registry (default)
"nginx:latest"
"myregistry.com/myapp:v1.0.0"
"gcr.io/project/image@sha256:abcd1234..."

// Local Docker daemon
"docker://nginx:latest"

// Tarball file
"file:///path/to/image.tar"
```

### Authentication Methods

#### 1. Unauthenticated (Public Images)

For public images that don't require authentication:

**YAML Configuration:**
```yaml
sources:
  - type: docker
    name: public-images
    docker:
      unauthenticated: {}
      images:
        - nginx:latest
        - alpine:3.18
```

**CLI Usage:**
```bash
trufflehog docker --image nginx:latest
```

---

#### 2. Basic Authentication

For private registries requiring username and password:

**YAML Configuration:**
```yaml
sources:
  - type: docker
    name: private-registry
    docker:
      basic_auth:
        username: myuser
        password: mypassword
      images:
        - myregistry.com/private-image:latest
        - myregistry.com/another-image:v1.0.0
```

**CLI Usage:**

Trufflehog does not provide basic authentication using username and password through CLI at the moment.

---

#### 3. Bearer Token

For registries using token-based authentication (e.g., Dockerhub registry):

**YAML Configuration:**
```yaml
sources:
  - type: docker
    name: truffle-packages
    docker:
      bearer_token: "ghp_xxxxxxxxxxxxxxxxxxxx"
      images:
        - myorg/myapp:latest
        - myorg/frontend:v2.1.0
```

**CLI Usage:**
```bash
trufflehog docker --image myorg/myapp:latest --bearer-token eyJ_xxxxxxxxxxxxxxxxxxxx
```

---

#### 4. Docker Keychain

Uses credentials from your local Docker configuration (`~/.docker/config.json`):

**YAML Configuration:**
```yaml
sources:
  - type: docker
    name: local-docker-creds
    docker:
      docker_keychain: true
      images:
        - myregistry.com/private-image:latest
        - docker.io/myorg/app:latest
```

**CLI Usage:**
```bash
# First, authenticate with Docker
docker login myregistry.com

# Then scan using stored credentials
trufflehog docker --image myregistry.com/private-image:latest
```

**Prerequisites:**
```bash
# Authenticate with your registry first
docker login
docker login ghcr.io
docker login quay.io

# Verify credentials are stored
cat ~/.docker/config.json
```

---

### Namespace Scanning (This feature is currently in beta version and under testing)

To scan **all images** under a namespace (organization or user):

**CLI Usage:**
```bash
# If no registry prefix is provided, Docker Hub is used by default
trufflehog docker --namespace myorg

# For other registries, include the registry prefix (e.g., quay.io, ghcr.io)
trufflehog docker --namespace quay.io/my_namespace
```

To include private images within that namespace:
```bash
trufflehog docker --namespace myorg --registry-token <access_token>
```

**YAML Configuration:**
```yaml
sources:
  - type: docker
    name: org-scan
    docker:
      namespace: myorg
      registry_token: "ghp_xxxxxxxxxxxxxxxxxxxx"
```

Supported registries:
- Docker Hub (`docker.io`)
- Quay (`quay.io`)
- GitHub Container Registry (`ghcr.io`)

This mode automatically enumerates all repositories within the specified namespace before scanning.

Note: According to the GHCR documentation, only GitHub Classic Personal Access Tokens (PATs) are currently supported for accessing container packages - including public ones.
Source: [GitHub Roadmap Issue #558](https://github.com/github/roadmap/issues/558)

---

### File Exclusion

Exclude specific files or directories from scanning using glob patterns:

```bash
trufflehog docker --image myregistry.com/private-image:latest --exclude-paths **/*.log
```

## How Image Scanning Works

### Scanning Process

1. **Image Retrieval**: Fetches the image from the specified source (registry, daemon, or file)
2. **History Scanning**: Extracts and scans image configuration history for secrets in build commands
3. **Layer Processing**: Iterates through each layer in parallel
4. **File Extraction**: Decompresses and extracts files from each layer
5. **Content Scanning**: Analyzes file contents for secrets and credentials
6. **Chunk Generation**: Emits chunks of data to the detection engine

### What Gets Scanned

- **Layer Contents**: All files within each image layer
- **Build History**: Commands used to build the image (FROM, RUN, ENV, etc.)
- **Configuration**: Environment variables and labels
- **Metadata**: Image annotations and custom metadata

### What Doesn't Get Scanned

- Files larger than 50MB (configurable limit)
- Files matching exclude patterns
- Empty layers (no content changes)

## Usage Examples

### Scanning a Public Image

```bash
trufflehog docker --image nginx:latest
```

### Scanning All Images Under a Namespace (Beta Version)

```bash
trufflehog docker --namespace trufflesecurity
```

Including private images:

```bash
trufflehog docker --namespace trufflesecurity --registry-token ghp_xxxxxxxxxxxxxxxxxxxx
```

### Scanning Multiple Images

```bash
trufflehog docker --image nginx:latest --image postgres:13 --image redis:alpine
```

### Scanning from Local Docker Daemon

```bash
trufflehog docker --image docker://myapp:local
```

### Scanning a Tarball

```bash
docker save myapp:latest -o myapp.tar
trufflehog docker --image file:///path/to/myapp.tar
```

### Scanning Private Registry with Authentication

```bash
docker login my-registry.io
trufflehog docker --image my-registry.io/private-app:v1.0.0
```

## Testing Results

| Test Case | Status | Command/Configuration | Registry URL | Notes |
|-----------|--------|----------------------|--------------|-------|
| Scan remote image on DockerHub | ✅ Success | `--image <image_name>` | https://hub.docker.com/ | Public images work without authentication |
| Scan specific tag of image on DockerHub | ✅ Success | `--image <image_name>:<tag_name>` | https://hub.docker.com/ | Tag specification working correctly |
| Scan all images under namespace | In Progress | `--namespace <namespace>` | DockerHub, Quay, GHCR | Automatically discovers all public images |
| Scan remote image on Quay.io | ✅ Success | `--image quay.io/prometheus/prometheus` | https://quay.io/search | Public Quay.io registry supported |
| Scan multiple images | ✅ Success | `--image <image_name> --image <image_name>` | Multiple registries | Sequential scanning of multiple images |
| Scan remote image on DockerHub with token | ✅ Success | `--token <token>`(Generate token using username and password) | https://hub.docker.com/ | Authenticated scanning for private repos |
| Scan private image on Quay | ⏸️ Halted | N/A | https://quay.io/ | RedHat requires paid account for private repos |
| Scan private image on GHCR | ✅ Success | `--image ghcr.io/<image_name>` | https://github.com/packages | GitHub Container Registry |

## Troubleshooting

### Common Issues

**Issue**: Authentication failures with private registries
**Solution**: Ensure credentials are correct and have pull permissions. Use `docker login` first when using Docker Keychain.

---

**Issue**: Out of memory errors with large images
**Solution**: Reduce concurrency or scan smaller images. Consider increasing available memory.

---

**Issue**: Slow scanning performance
**Solution**: Enable concurrent processing, use local daemon instead of remote registry, or exclude unnecessary directories.

---

**Issue**: Files not being scanned
**Solution**: Check exclude patterns and file size limits. Verify files are under 50MB.
