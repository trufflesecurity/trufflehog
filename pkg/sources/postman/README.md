# Postman Source

## Overview

The Postman source lets TruffleHog scan Postman workspaces, collections, and environments for secrets, credentials, and sensitive data. It can read data live from the Postman API with a token, or from files exported from Postman and saved on disk.

## Postman Fundamentals

### What does this source scan?

This source reads Postman data, walks through it piece by piece, and sends text built from each piece to the detection engine. This includes variables, request details, scripts, authorization settings, and saved example responses.

### Key Postman Terminology

| Term | Description |
|------|-------------|
| **Workspace** | A place in Postman that groups collections and environments together |
| **Collection** | A group of saved requests and folders |
| **Folder** | A container inside a collection that groups requests and other folders |
| **Request** | A single saved API call, with a URL, headers, body, and authorization settings |
| **Environment** | A named set of variables, such as one for testing and one for production |
| **Variable** | A name and value pair. Requests refer to a variable by writing its name inside double curly braces, such as `{{api_key}}` |
| **Script** | Code that runs before a request is sent or after a response comes back |
| **UID** | The full ID of a Postman item, which is the owner's ID joined to the item's own ID |

## Features

- **API and File Scanning**: Read live data from the Postman API with a token, or scan files exported from Postman
- **Variable Substitution**: When text uses a variable like `{{api_key}}` and the variable's value is known, TruffleHog scans the text with the real value filled in
- **Collection and Environment Filtering**: Include or exclude specific collections and environments by ID
- **API Rate Limit Safety**: Slows down to stay within Postman's request limits, and stops the scan if most of the monthly request limit has been used

## Configuration

### Authentication Methods

#### 1. API Token

**CLI Usage:**
```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Postman
    token: "PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  name: postman-scan
  type: SOURCE_TYPE_POSTMAN
  verify: true
```

On the CLI, the token can also be set with the `POSTMAN_TOKEN` environment variable instead of `--token`. This does not apply to a YAML config file, since TruffleHog does not read environment variables while loading YAML.

---

#### 2. Unauthenticated (Exported Files Only)

Used when scanning files that were already exported from Postman and saved on disk. No API calls are made.

**CLI Usage:**

Leave out `--token` and give at least one of the file path flags. The CLI picks this mode automatically. If neither a token nor a file path is given, the CLI stops with `no path to locally exported data or API token provided`.

```bash
trufflehog postman --collection-paths /path/to/collection.json
```

**YAML Configuration:**

In the YAML config, this must be set explicitly.

```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.Postman
    unauthenticated: {}
    collection_paths:
    - /path/to/collection.json
  name: postman-scan
  type: SOURCE_TYPE_POSTMAN
  verify: true
```

### Choosing What to Scan

**Scan Everything a Token Can See**

If a token is given and no `--workspace-id`, `--collection-id`, or `--environment` is named, TruffleHog lists every workspace the token can see and scans them all. Exported file paths do not turn this off, so a token given together with file paths scans both.

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Scan Specific Workspaces**

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --workspace-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

`--workspace-id` can be repeated. Each workspace is scanned along with its environments and collections. This needs a token.

**Scan Specific Collections**

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --collection-id 12345678-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

`--collection-id` can be repeated. TruffleHog's code expects the collection's UID here, which is the owner's ID joined to the collection's own ID. This needs a token.

**Scan Exported Files**

```bash
trufflehog postman --workspace-paths /path/to/workspace.zip --collection-paths /path/to/collection.json --environment-paths /path/to/environment.json
```

Each of these three flags can be repeated.

- A workspace path must be a `.zip` file. Any other file type is silently ignored. Inside the zip, TruffleHog reads the files whose names contain `collection` or `environment`.
- A collection path is a collection exported as a `.json` file.
- An environment path is an environment exported as a `.json` file.

If a local file cannot be read or cannot be parsed, the whole scan stops with that error.

**The `--environment` Flag**

`--environment` is accepted, but TruffleHog does not currently scan an environment by its ID. It only has one effect: naming an environment this way turns off the "scan everything a token can see" behavior described above. Use `--workspace-id`, or `--environment-paths` for an exported file, to scan environments.

### Filtering What Gets Scanned

**Include or Exclude Collections**

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --include-collection-id 12345678-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --exclude-collection-id 12345678-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

These apply to collections found through the API, both ones given with `--collection-id` and ones found inside a workspace. They do not apply to exported files given with `--collection-paths`. Values are compared as exact text against the collection ID being scanned, which is the UID for a collection found inside a workspace and the value you passed for `--collection-id`. The filters do not use glob patterns.

**Include or Exclude Environments**

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --include-environments 12345678-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --exclude-environments 12345678-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

These apply to environments found inside a workspace. They do not apply to exported files given with `--environment-paths`. Values must match the environment's UID exactly.

**Which Wins**

For both collections and environments, an item on the exclude list is always skipped, even if it is also on the include list. If an include list is given, only items on it are scanned.

**Number of Workers**

There is no concurrency for this source. Everything is fetched and scanned one item at a time, and there is no flag to change that.

## How Scanning Works

### Scanning Process

1. **Local Files**: Reads every file given with `--environment-paths`, `--collection-paths`, and `--workspace-paths`, in that order
2. **Workspaces**: For each workspace given with `--workspace-id`, fetches the workspace from the API, scans its environments, then scans its collections
3. **Collections**: For each collection given with `--collection-id`, fetches it from the API and scans it
4. **Everything a Token Can See**: If a token was given and no workspace, collection, or environment was named, lists all workspaces and scans each one the same way
5. **Variable Substitution**: Variables are collected as scanning goes. When text contains a variable such as `{{api_key}}` and its value is known, TruffleHog scans the text with the real value filled in, in place of the original text with the variable name. If a value uses other variables, this repeats a few times and then stops at a fixed limit. A collection's own variables are only filled into that same collection
6. **Keyword Hints**: As TruffleHog walks through workspace, collection, folder, request, and variable names and values, it notes any that contain words the detectors look for. It then writes the text it scans as lines in the form `keyword:text`, one line per noted keyword. This helps detectors that need a nearby hint word to fire. The noted keywords start over for each workspace

### What Gets Scanned

- Variables in environments, collections, request and response headers, query parameters, and form bodies
- Collection, folder, and request authorization settings of these types: API key, AWS signature, bearer token, basic auth, and OAuth 2.0
- Pre-request and test scripts at the collection, folder, and request level
- Request headers, the request URL without its query string, and query parameters
- Request bodies in raw, form data, URL encoded, and GraphQL formats
- Saved example responses, including their headers, bodies, and the original request they were made from

### What Doesn't Get Scanned

- Any piece of text seen before TruffleHog has noted at least one detector keyword, since there is then nothing to write the `keyword:text` lines with and that piece is skipped. In practice, a workspace with no names, variable names, or values that contain a detector keyword sends nothing to the detectors
- A request body sent as a file
- Variables defined on a folder or a request, only environment, collection, header, query, and form variables are read
- Request and collection descriptions
- Authorization settings of any other type, and requests marked as having no authorization
- Items skipped by the include and exclude filters
- Workspaces, collections, and environments that the API cannot return for this token, for example because of a permission error. These are logged and skipped without stopping the scan

### API Limits

The Postman API allows only a few calls per second. TruffleHog waits between calls to stay under that: about 1 call per second for workspace and collection requests, and about 5 per second for environment requests. If the response headers show that more than 80 percent of the monthly request limit has been used, TruffleHog stops the scan instead of using up the rest.

## Usage Examples

### Scanning Everything a Token Can See

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning One Workspace

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --workspace-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

### Scanning a Workspace Without Scanning One Collection

```bash
trufflehog postman --token PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --workspace-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee --exclude-collection-id 12345678-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

### Scanning Exported Files

```bash
trufflehog postman --collection-paths /path/to/collection.json --environment-paths /path/to/environment.json
```

## Troubleshooting

### Common Issues

**Issue**: `no path to locally exported data or API token provided`
**Solution**: Pass `--token` to read from the API, or pass at least one of `--workspace-paths`, `--collection-paths`, or `--environment-paths` to scan exported files.

---

**Issue**: `Postman token is empty`
**Solution**: In a YAML config, the `token` field was set but left blank. Provide a real token.

---

**Issue**: `credential type not implemented for Postman`
**Solution**: In a YAML config, no credential was set. Set either `token` or `unauthenticated: {}`.

---

**Issue**: `aborting scan due to Postman API monthly requests limit being used over 80.000000%`
**Solution**: Most of the monthly Postman API request limit has been used, so the scan stopped on purpose. Wait for the limit to reset, or scan exported files instead, which do not use the API.

---

**Issue**: A workspace, collection, or environment is missing from the scan
**Solution**: Check the token has access to it. The Postman API sometimes lists items the token cannot read, and these are logged and skipped. Also check it is not on an exclude list, or left off an include list.

---

**Issue**: Scanning with only `--environment` finds nothing
**Solution**: `--environment` does not scan an environment on its own. Use `--workspace-id` to scan the workspace that holds it, or `--environment-paths` to scan an exported environment file.
