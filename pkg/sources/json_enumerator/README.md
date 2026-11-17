# JSON Enumerator Source

## Overview

The JSON enumerator source lets TruffleHog scan data that another tool has already collected, for secrets, credentials, and sensitive data. The data is written to one or more files as a stream of JSON entries, each holding some data to scan and some metadata about where it came from. TruffleHog scans the data and copies the metadata into each result.

## JSON Enumerator Fundamentals

### What does this source scan?

This source reads the files given to it and scans the `data` of every entry in them. It does not connect to any service or need any credentials. It is useful when another tool fetches content from a system TruffleHog has no source for, and wants TruffleHog to do the scanning.

### Key Terminology

| Term | Description |
|------|-------------|
| **Enumerator file** | A file holding a stream of JSON entries, usually one per line |
| **Entry** | One JSON object in the file, with `metadata` and either `data` or `data_b64` |
| **Metadata** | Any JSON value describing where the data came from. It is copied into results as is |

## Features

- **Any Content**: Scan content from any system, as long as it can be written as JSON entries
- **Binary Data**: Data that is not valid UTF-8 can be sent base64 encoded in `data_b64`
- **Compressed Files**: Files ending in `.zst` or `.zstd` are decompressed with zstd while they are read
- **Archive Support**: Archives inside an entry's data are unpacked and their contents are scanned
- **Custom Result Metadata**: Each result carries the metadata of the entry it was found in

## Configuration

### File Format

Each entry is a JSON object:

```json
{"metadata": {"url": "https://example.com/page/1"}, "data": "text to scan"}
{"metadata": {"url": "https://example.com/file.bin"}, "data_b64": "AAECAwQ="}
```

- `metadata` is required and can be any JSON value except `null`.
- Exactly one of `data` (a string) or `data_b64` (base64 encoded bytes) must be set.

Entries are read one after another, so one per line works, but any whitespace between them is fine.

### CLI Usage

```bash
trufflehog json-enumerator entries.jsonl
```

Several files can be given at once:

```bash
trufflehog json-enumerator part1.jsonl part2.jsonl.zst
```

### YAML Configuration

```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.JSONEnumerator
    paths:
    - "/path/to/entries.jsonl"
  name: json-enumerator-scan
  type: SOURCE_TYPE_JSON_ENUMERATOR
  verify: true
```

TruffleHog's global flags still apply, such as `--json`, `--no-verification`, `--concurrency`, and the archive flags.

## How Scanning Works

### Scanning Process

1. **Enumeration**: Each path is one unit. Paths that cannot be opened are reported as errors
2. **Decompression**: Files ending in `.zst` or `.zstd` are decompressed while they are read
3. **Decoding**: Entries are decoded one at a time
4. **Scanning**: Each entry's data is checked for its type, archives are unpacked, and the content is split into pieces and sent to the detection engine with the entry's metadata

### What Gets Scanned

- The `data` or `data_b64` of every entry in every given file
- The contents of archives inside an entry's data, unless archive scanning is turned off with `--force-skip-archives`

### What Doesn't Get Scanned

- Files that cannot be opened
- Every entry after a bad one in the same file. A bad entry (invalid JSON, missing `metadata`, or neither or both of `data` and `data_b64`) stops the scan of that file, since TruffleHog cannot tell where the next entry starts. Entries before it are still scanned, and other files are not affected
- Entries with empty data

## Usage Examples

### Scanning One File

```bash
trufflehog json-enumerator entries.jsonl
```

### Scanning a Compressed File

```bash
trufflehog json-enumerator entries.jsonl.zst
```

### Scanning With JSON Output

```bash
trufflehog json-enumerator entries.jsonl --json
```

## Debug Logs

With debug on for this source, the scan logs:

- `V(1)`: `JSON enumerator source initialized` with the number of paths, and `Enumerated paths` with how many could be opened and how many could not.
- `V(2)`: `Scanning file` with its `path` and whether it is `zstd`, and `Finished scanning file` with the number of `entries` decoded and its `duration`. If `entries` is lower than expected, a bad entry stopped the file.
- `V(3)`: `Scanning entry` for each entry, with its `entry` number (counting from 0) and `data_bytes`.
- `V(5)`: `empty reader, skipping file` for an entry with empty data, and `skipping archive file` when archive data is skipped with `--force-skip-archives`.

Entry metadata and data are never logged. Files that cannot be opened, a bad entry (`decoding entry N: ...`), and an entry that fails to scan are logged as errors at the default level, with the `entry` number where it applies.

## Troubleshooting

### Common Issues

**Issue**: `decoding entry N: missing metadata`
**Solution**: Entry `N` (counting from 0) has no `metadata`, or it is `null`. Every entry needs a `metadata` value, even if it is just `{}`.

---

**Issue**: `decoding entry N: both data and data_b64 missing` or `both data and data_b64 present`
**Solution**: Set exactly one of `data` or `data_b64` on entry `N`.

---

**Issue**: Some entries in a file were not scanned
**Solution**: Look for a `decoding entry N` error. Entries after a bad entry in the same file are not scanned. Fix entry `N` and scan the file again.

---

**Issue**: `decoding entry 0: invalid input: magic number mismatch`
**Solution**: The file ends in `.zst` or `.zstd` but is not zstd compressed. Rename it, or compress it with zstd.
