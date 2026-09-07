# Filesystem Source

## Overview

The Filesystem source lets TruffleHog scan files and directories on local disk for secrets, credentials, and sensitive data. It can scan a single file, walk a whole directory tree, or follow symlinks to files and directories outside the given path.

## Filesystem Fundamentals

### What does this source scan?

This source scans paths on the machine running TruffleHog. A path can point to a single file, a directory, or a symlink. When a directory is given, TruffleHog walks every file inside it, including files in subdirectories.

### Key Terminology

| Term | Description |
|------|-------------|
| **Path** | A file or directory location to scan. You can list more than one |
| **Symlink** | A file that points to another file or directory instead of holding data itself |
| **Symlink Depth** | How many symlinks in a row TruffleHog will follow before it stops, to avoid following a loop forever |
| **Include Paths File** | A file with a list of patterns. Only files matching one of these patterns are scanned |
| **Exclude Paths File** | A file with a list of patterns. Files matching one of these patterns are skipped |
| **Binary File** | A file that is not plain text, such as an image or a compiled program |
| **Resume Info** | Progress information saved during a scan so a long scan can continue where it left off after a restart |

## Features

- **File and Directory Scanning**: Scan a single file or an entire directory tree
- **Symlink Support**: Optionally follow symlinks to files and directories, up to a configured depth
- **Path Filtering**: Include or exclude files using pattern files
- **Binary File Skipping**: Optionally skip files that are not plain text
- **Concurrent Processing**: Files within a directory are scanned in parallel
- **Resumable Scans**: A scan that stops partway through a large directory can pick up from where it stopped

## Configuration

### Scanning Paths

**CLI Usage:**
```bash
trufflehog filesystem /var/log /home/user/project/config.yaml
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Filesystem
    paths:
    - /var/log
    - /home/user/project/config.yaml
  name: local-scan
  type: SOURCE_TYPE_FILESYSTEM
  verify: true
```

You can also pass directories using the `--directory` flag, which can be repeated:

```bash
trufflehog filesystem --directory /var/log --directory /etc
```

### Following Symlinks

By default, symlinks are not followed. Set a maximum depth to allow TruffleHog to follow them.

**CLI Usage:**
```bash
trufflehog filesystem /home/user/project --max-symlink-depth 5
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Filesystem
    paths:
    - /home/user/project
    max_symlink_depth: 5
  name: local-scan
  type: SOURCE_TYPE_FILESYSTEM
  verify: true
```

The highest depth allowed is 40. Setting a higher number will cause the scan to fail with an error at startup.

### Skipping Binary Files

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Filesystem
    paths:
    - /home/user/project
    skip_binaries: true
  name: local-scan
  type: SOURCE_TYPE_FILESYSTEM
  verify: true
```

### Path Filtering

Use plain text files with one pattern per line to include or exclude files from a scan.

**CLI Usage:**
```bash
trufflehog filesystem /home/user/project --include-paths /home/user/include-patterns.txt --exclude-paths /home/user/exclude-patterns.txt
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Filesystem
    paths:
    - /home/user/project
    include_paths_file: /home/user/include-patterns.txt
    exclude_paths_file: /home/user/exclude-patterns.txt
  name: local-scan
  type: SOURCE_TYPE_FILESYSTEM
  verify: true
```

## How Scanning Works

### Scanning Process

1. **Path Check**: For each configured path, TruffleHog checks whether it is a file, a directory, or a symlink
2. **Directory Walk**: If it is a directory, every entry inside is visited. Subdirectories are visited the same way, going deeper until every file is reached
3. **Symlink Handling**: If an entry is a symlink and following symlinks is turned on, TruffleHog follows it to the file or directory it points to, up to the configured depth
4. **File Filtering**: Each file is checked against the include and exclude patterns before it is scanned
5. **Binary Check**: If skipping binaries is turned on, files that look like binary files are skipped
6. **Content Scanning**: The file is opened and its content is sent to the detection engine as chunks
7. **Progress Tracking**: The path of the last file scanned in each directory is saved, so a scan that stops can resume from that point

### What Gets Scanned

- Regular files at the given paths
- Files inside directories at the given paths, including subdirectories
- Files reached by following a symlink, when symlink following is turned on

### What Doesn't Get Scanned

- Symlinks, when symlink following is turned off
- Files that go past the configured maximum symlink depth
- Files matching an exclude pattern, or not matching an include pattern, when pattern files are set
- Binary files, when skipping binaries is turned on
- Files that are not regular files, such as device files or sockets

## Usage Examples

### Scanning a Single File

```bash
trufflehog filesystem /home/user/project/config.yaml
```

### Scanning a Directory

```bash
trufflehog filesystem /home/user/project
```

### Scanning Multiple Paths

```bash
trufflehog filesystem /home/user/project /var/log/app.log
```

### Scanning a Directory and Following Symlinks

```bash
trufflehog filesystem /home/user/project --max-symlink-depth 10
```

### Scanning While Skipping Binary Files

```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Filesystem
    paths:
    - /home/user/project
    skip_binaries: true
  name: local-scan
  type: SOURCE_TYPE_FILESYSTEM
  verify: true
```

## Troubleshooting

### Common Issues

**Issue**: Symlinks are not being scanned
**Solution**: Set `max_symlink_depth` (or `--max-symlink-depth`) to a value greater than zero. Symlinks are skipped by default.

---

**Issue**: `specified symlink depth exceeds the allowed max`
**Solution**: The maximum allowed symlink depth is 40. Use a smaller value.

---

**Issue**: Some files are missing from scan results
**Solution**: Check the include and exclude pattern files for a pattern that matches those files, and confirm `skip_binaries` is not turned on for text files that look like binary data.

---

**Issue**: A restarted scan seems to repeat or skip files
**Solution**: Resume tracking saves the last file scanned inside each directory. If the directory contents changed between runs, the resume point may no longer line up with the same files.
