# Elasticsearch Source

## Overview

The Elasticsearch source lets TruffleHog scan documents stored in an Elasticsearch cluster for secrets, credentials, and sensitive data. It connects to the cluster, finds matching indices, and reads the documents inside them.

## Elasticsearch Fundamentals

### What is Elasticsearch?

Elasticsearch is a search and analytics engine that stores data as documents inside indices. It is often used to store and search logs, so many logging tools send their log lines into Elasticsearch as documents.

### Key Elasticsearch Terminology

| Term | Description |
|------|-------------|
| **Node** | A single running instance of Elasticsearch. A cluster is made of one or more nodes |
| **Cluster** | A group of nodes working together and holding the same data |
| **Index** | A collection of documents, similar to a table in a normal database |
| **Document** | A single record stored inside an index, in JSON format |
| **Cloud ID** | An identifier used to connect to a managed Elastic Cloud deployment without listing node addresses |
| **API Key** | A credential used to authenticate API requests without a username and password |
| **Service Token** | A credential tied to a specific Elasticsearch service account |
| **Point in Time (PIT)** | A snapshot of the index state used so a search can page through results safely while data keeps changing |

## Features

- **Multiple Connection Methods**: Connect using node addresses or an Elastic Cloud ID
- **Multiple Authentication Methods**: Username and password, API key, or service token
- **Index Filtering**: Limit scanning to indices matching a pattern
- **Document Filtering**: Limit scanning to documents matching a query, or created after a timestamp
- **Concurrent Processing**: Documents are scanned in parallel across a configurable number of workers
- **Continuous Scanning**: Optionally keep scanning a live cluster and pick up new documents as they arrive
- **Duplicate Avoidance**: Tracks the newest document timestamp per index so already seen documents are not scanned again on the next run

## Configuration

### Connecting to a Cluster

You can connect using node addresses:

```yaml
sources:
  - type: elasticsearch
    name: es-scan
    elasticsearch:
      nodes:
        - "https://localhost:9200"
```

Or using an Elastic Cloud ID:

```yaml
sources:
  - type: elasticsearch
    name: es-cloud-scan
    elasticsearch:
      cloud_id: "my-deployment:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=="
```

**CLI Usage:**
```bash
trufflehog elasticsearch --nodes https://localhost:9200
```

### Authentication Methods

#### 1. Username and Password

```yaml
sources:
  - type: elasticsearch
    name: es-scan
    elasticsearch:
      nodes:
        - "https://localhost:9200"
      username: elastic
      password: mypassword
```

**CLI Usage:**
```bash
trufflehog elasticsearch --nodes https://localhost:9200 --username elastic --password mypassword
```

---

#### 2. API Key

```yaml
sources:
  - type: elasticsearch
    name: es-scan
    elasticsearch:
      nodes:
        - "https://localhost:9200"
      api_key: "xxxxxxxxxxxxxxxxxxxxxxxx"
```

**CLI Usage:**
```bash
trufflehog elasticsearch --nodes https://localhost:9200 --api-key xxxxxxxxxxxxxxxxxxxxxxxx
```

---

#### 3. Service Token

```yaml
sources:
  - type: elasticsearch
    name: es-scan
    elasticsearch:
      nodes:
        - "https://localhost:9200"
      service_token: "AAEAAWVsYXN0aWMv..."
```

**CLI Usage:**
```bash
trufflehog elasticsearch --nodes https://localhost:9200 --service-token AAEAAWVsYXN0aWMv...
```

Environment variables are also supported for every value above: `ELASTICSEARCH_NODES`, `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_CLOUD_ID`, `ELASTICSEARCH_API_KEY`, and `ELASTICSEARCH_SERVICE_TOKEN`.

### Filtering What Gets Scanned

**Index Pattern**

Limit scanning to indices matching a pattern. The default is `*`, which matches every index.

```bash
trufflehog elasticsearch --nodes https://localhost:9200 --index-pattern "logs-*"
```

**Query JSON**

Provide a raw Elasticsearch query to filter which documents are scanned.

```bash
trufflehog elasticsearch --nodes https://localhost:9200 --query-json '{"match": {"level": "error"}}'
```

**Since Timestamp**

Only scan documents with a `@timestamp` field on or after the given time. This is ignored once TruffleHog has already recorded a newer timestamp from a previous scan of that index.

```bash
trufflehog elasticsearch --nodes https://localhost:9200 --since-timestamp "2024-01-01T00:00:00Z"
```

### Best Effort Scan

By default, TruffleHog scans the matching documents once and stops. Pass `--best-effort-scan` to keep the source running and repeatedly check the cluster for new documents.

```bash
trufflehog elasticsearch --nodes https://localhost:9200 --best-effort-scan
```

## How Scanning Works

### Scanning Process

1. **Index Discovery**: Lists indices matching the configured index pattern
2. **Document Counting**: Counts matching documents in each index using the configured query and timestamp filters
3. **Work Distribution**: Splits the documents to scan into roughly equal groups across the configured number of workers
4. **Point in Time Search**: Each worker opens a point in time on its assigned index and pages through matching documents in order
5. **Document Scanning**: Each document's `message` field is sent to the detection engine as a chunk, tagged with the index name, document id, and timestamp
6. **Progress Tracking**: The newest document timestamp seen in each index is recorded, so a later run or a best effort scan loop can skip documents already scanned

### What Gets Scanned

- The `message` field of documents in indices matching the index pattern and query filters

### What Doesn't Get Scanned

- Documents outside the configured index pattern, query, or since timestamp filter
- Fields other than `@timestamp` and `message`

## Usage Examples

### Scanning a Local Cluster

```bash
trufflehog elasticsearch --nodes https://localhost:9200 --username elastic --password mypassword
```

### Scanning an Elastic Cloud Deployment

```bash
trufflehog elasticsearch --cloud-id "my-deployment:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==" --api-key xxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning Only Log Indices Created Since a Given Date

```bash
trufflehog elasticsearch --nodes https://localhost:9200 --index-pattern "logs-*" --since-timestamp "2024-06-01T00:00:00Z"
```

### Continuously Scanning a Live Cluster

```bash
trufflehog elasticsearch --nodes https://localhost:9200 --best-effort-scan
```

## Troubleshooting

### Common Issues

**Issue**: Authentication failures when connecting to the cluster
**Solution**: Check that the username, password, API key, or service token is correct and has permission to read the target indices.

---

**Issue**: No documents are scanned even though the cluster has data
**Solution**: Check the index pattern matches real index names, and that the query JSON or since timestamp filter is not excluding every document.

---

**Issue**: Scanning is slow on a large cluster
**Solution**: Increase the number of workers used for concurrency, or narrow the index pattern and query to scan fewer documents at a time.

---

**Issue**: The same documents keep getting scanned again on every run
**Solution**: This is expected the first time a since timestamp is used. On later runs TruffleHog uses the newest timestamp already seen, so the same documents are skipped unless best effort scan restarts from the same state.
