# Stdin Source

## Overview

The stdin source lets TruffleHog scan data that is piped into it from another command, for secrets, credentials, and sensitive data. It reads everything from standard input until the input ends, and scans it.

## Stdin Fundamentals

### What does this source scan?

This source scans whatever is sent to TruffleHog's standard input. It does not connect to any service, read any file by name, or need any credentials.

### Key Terminology

| Term | Description |
|------|-------------|
| **Standard Input (stdin)** | The stream a command reads its input from. A pipe connects the output of one command to the stdin of the next |
| **Pipe** | The `\|` symbol in a shell, which sends the output of the command on its left into the command on its right |

## Features

- **No Setup**: No flags, credentials, or config needed
- **Works With Any Command**: Scan the output of any command that can write to a pipe
- **Archive Support**: Archives piped in are unpacked and their contents are scanned

## Configuration

This source has no options of its own. The only way to run it is the `stdin` command on the CLI:

```bash
trufflehog stdin
```

Note: as of this writing, `pkg/config/config.go` does not have a case for the stdin source type in its source loader, so a YAML `--config` file cannot be used for it.

TruffleHog's global flags still apply, such as `--json`, `--no-verification`, `--force-skip-archives`, `--archive-max-size`, `--archive-max-depth`, and `--archive-timeout`.

There is no way to set the number of workers for this source. It reads one input stream from start to end.

## How Scanning Works

### Scanning Process

1. **Read Input**: Reads from standard input until the input ends
2. **Detect Type**: Checks what kind of data it is. Archive formats that TruffleHog supports are unpacked, and everything else is scanned as it is
3. **Scan**: Splits the data into pieces and sends them to the detection engine

### What Gets Scanned

- Everything read from standard input
- The contents of archives piped in, unless archive scanning is turned off with `--force-skip-archives`

### What Doesn't Get Scanned

- Empty input. If nothing is piped in, TruffleHog finishes without results and without an error
- Archive contents, when `--force-skip-archives` is set

### Result Details

Results from this source do not include a file name, line number, or link. The stdin source has no location fields to fill in, and line numbers are not added for it.

### Time Limit

The time limit set with `--archive-timeout` is 60 seconds by default. It is applied to the whole time TruffleHog spends processing the piped input, not only to unpacking archives. If your input takes longer than that to read and process, raise it with `--archive-timeout`.

## Usage Examples

### Scanning the Output of a Command

```bash
cat config.yaml | trufflehog stdin
```

### Scanning the Output of Another Tool

```bash
git diff | trufflehog stdin
```

### Scanning a Log Stream

```bash
docker logs my-container 2>&1 | trufflehog stdin
```

### Scanning With JSON Output

```bash
cat config.yaml | trufflehog stdin --json
```

## Troubleshooting

### Common Issues

**Issue**: The command seems to hang and does nothing
**Solution**: With nothing piped in, TruffleHog waits for input and keeps reading until the input ends. Pipe a command into it, or redirect a file into it with `trufflehog stdin < file`.

---

**Issue**: No results and no error
**Solution**: Check the piped command actually printed something. Empty input is skipped without an error.

---

**Issue**: Results do not say where the secret was found
**Solution**: This is expected. The stdin source does not attach a file name, line number, or link to its results.

---

**Issue**: A long running stream stops being scanned partway through
**Solution**: Check the time limit. It defaults to 60 seconds and can be raised with `--archive-timeout`.
