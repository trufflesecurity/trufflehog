# Syslog Source

## Overview

The Syslog source lets TruffleHog listen for syslog messages sent over the network and scan each message for secrets, credentials, and sensitive data. Instead of reading stored data, it opens a port and scans whatever arrives, so it keeps running until you stop it.

## Syslog Fundamentals

### What does this source scan?

This source starts a network listener. Every piece of data that arrives on that port is sent to the detection engine. It does not read log files from disk. To scan a log file, use the filesystem source.

### Key Syslog Terminology

| Term | Description |
|------|-------------|
| **Syslog** | A standard way for machines and programs to send log messages over a network |
| **RFC 3164** | The older syslog message format |
| **RFC 5424** | The newer syslog message format. It carries more fields, such as the app name and process ID |
| **UDP** | A network protocol that sends each message on its own, with no connection |
| **TCP** | A network protocol that keeps a connection open between the sender and the listener |
| **TLS** | Encryption for a TCP connection. It needs a certificate and a key |

## Features

- **Live Listening**: Scans messages as they arrive, with no need to store them first
- **UDP or TCP**: Listens on either protocol
- **TLS Support**: Can accept encrypted TCP connections with your own certificate and key
- **Two Message Formats**: Reads RFC 3164 or RFC 5424 headers to fill in details about where a message came from
- **Safe Fallback**: A message that does not match the chosen format is still scanned, just without those details

## Configuration

### Authentication

There are no credentials. TruffleHog is the one receiving data, so nothing is fetched from a remote service and there is nothing to log in to.

### CLI Options

**CLI Usage:**
```bash
trufflehog syslog --format rfc3164
```

| Flag | Description | Default |
|------|-------------|---------|
| `--format` | Message format. Either `rfc3164` or `rfc5424`. The CLI requires this flag | None |
| `--address` | Address and port to listen on, for example `127.0.0.1:514` | `:5140` |
| `--protocol` | `udp` or `tcp` | `udp`, or `tcp` if a certificate and key are given |
| `--cert` | Path to a TLS certificate file | None |
| `--key` | Path to a TLS key file | None |

An address that starts with a colon, such as the default `:5140`, listens on all network interfaces.

### YAML Configuration

This source cannot be used from a `--config` YAML file. The YAML loader has no case for syslog, so use the CLI command above.

### Using TLS

```bash
trufflehog syslog --protocol tcp --address 0.0.0.0:6514 --format rfc5424 --cert /path/to/server.crt --key /path/to/server.key
```

- Give both `--cert` and `--key`. If only one of them is given, the CLI ignores it without any error, and the listener starts without TLS.
- If a certificate and key are given and `--protocol` is left out, the protocol becomes `tcp`.
- TLS over UDP is not supported. Asking for it stops the scan with `TLS is not supported over UDP`.

### Number of Workers

This is not configurable. The global `--concurrency` flag is accepted by the command, but the syslog source does not use it. Each TCP connection is handled on its own, and the UDP listener reads one message at a time.

## How Scanning Works

### Scanning Process

1. **Start Listening**: Opens a UDP or TCP listener on the address. A TLS listener is used if a certificate and key were given
2. **Receive Data**:
   - **UDP**: Reads one datagram at a time, with room for up to 65535 bytes
   - **TCP**: Accepts each new connection and reads from it in pieces of up to 8096 bytes
3. **Read the Header**: Tries to read the message header using the chosen format, to fill in details such as the host name. If this fails, the failure is logged at a low log level and the message goes on with empty details
4. **Scan**: Sends the received bytes to the detection engine as one chunk

The scan does not finish on its own. It runs until TruffleHog is stopped, for example with Ctrl+C.

### Message Details

When the header can be read, each result carries these details:

| Detail | RFC 3164 | RFC 5424 |
|--------|----------|----------|
| Host name | Yes | Yes |
| App name | No | Yes |
| Process ID | No | Yes |
| Timestamp | Yes | Yes |
| Facility | Yes | No |
| Client (sender address and port) | Yes | Yes |

### Limits to Know About

- **No message framing on TCP**: TruffleHog does not split TCP data into lines or messages. One read becomes one chunk. Several small messages sent close together can land in the same chunk, and a message longer than 8096 bytes is split across chunks.
- **Unused buffer space**: The received buffer is passed on whole, without being trimmed to the number of bytes that arrived.
- **Default format**: If no format is given at all, `rfc3164` is used. The CLI always requires `--format`, so this only matters outside the CLI.
- **Verification**: The usual `--no-verification` flag still turns off verification for syslog results.

## Usage Examples

### Listen for UDP on the Default Port

```bash
trufflehog syslog --format rfc3164
```

### Listen for RFC 5424 Messages on TCP

```bash
trufflehog syslog --protocol tcp --address 0.0.0.0:514 --format rfc5424
```

### Listen with TLS

```bash
trufflehog syslog --protocol tcp --address 0.0.0.0:6514 --format rfc5424 --cert /path/to/server.crt --key /path/to/server.key
```

## Troubleshooting

### Common Issues

**Issue**: `required flag(s) --format not provided`
**Solution**: Add `--format rfc3164` or `--format rfc5424` to the command.

---

**Issue**: `TLS is not supported over UDP`
**Solution**: Use `--protocol tcp` with `--cert` and `--key`, or remove the certificate and key to use UDP.

---

**Issue**: `error creating UDP listener` or `error creating TCP listener`
**Solution**: The address is already in use, or you are not allowed to use it. Ports below 1024 usually need extra permission, so try a higher port such as the default `5140`.

---

**Issue**: `unknown connection type`
**Solution**: `--protocol` was set to something other than `udp` or `tcp`. Use one of those two values.

---

**Issue**: `could not open TLS cert file` or `could not open TLS key file`
**Solution**: Check that the `--cert` and `--key` paths exist and can be read.

---

**Issue**: TLS is not being used even though only `--cert` or only `--key` was given
**Solution**: Give both. One alone is ignored.

---

**Issue**: Results have no host name or other details
**Solution**: The message did not match the chosen format. Check that `--format` matches what your senders use. The message is still scanned.
