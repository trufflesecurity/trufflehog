# TruffleHog Web Source

Crawls and scans websites for secrets and sensitive information using the [Colly](http://go-colly.org/) web scraping framework.

## Configuration

### Required

| Flag | Description |
|------|-------------|
| `--url` | URL to scan. Repeat for multiple targets: `--url https://a.com --url https://b.com`. Supports `http://` and `https://`. |

### Optional

| Flag | Default | Description |
|------|---------|-------------|
| `--crawl` | `false` | Follow links found on each page. Without this flag only the seed URL(s) are scanned. |
| `--depth` | `1` | Maximum link depth to follow when `--crawl` is enabled. `1` = seed; `2` = one level deeper; `0` = unlimited. Has no effect without `--crawl`. |
| `--delay` | `1` | Seconds to wait between requests to the same domain. Increase this to reduce load on the target server. |
| `--timeout` | `30` | Seconds to spend crawling each URL before aborting. Applied independently per URL. |
| `--user-agent` | TruffleHog identifier | User-Agent header sent with each request. |
| `--ignore-robots` | `false` | Ignore `robots.txt` restrictions. Only enable this if you have explicit permission to crawl the target site. |

## Usage

**Scan a single page (no crawling)**
```bash
trufflehog web --url https://example.com
```

**Scan a page and its direct links**
```bash
trufflehog web --url https://example.com --crawl --depth 2 --delay 2
```

**Scan multiple URLs two levels deep**
```bash
trufflehog web \
  --url https://example.com \
  --url https://app.example.com \
  --crawl \
  --depth 3 \
  --delay 1
```

**Scan with a short per-URL timeout**
```bash
trufflehog web --url https://example.com --crawl --depth 2 --timeout 60
```

## Behavior

### Domain scope

The crawler visits the exact domain provided and all of its subdomains. External links to other domains are always skipped.

### Depth counting

Depth is counted in hops from the seed URL. The seed itself is hop 1; pages linked directly from it are hop 2, and so on. Setting `--depth 0` with `--crawl` enables unlimited traversal.

### Robots.txt

Robots.txt rules are respected by default. Disabling this with `--ignore-robots` should only be done with explicit permission from the site owner.

## Output

Each crawled page produces a chunk with the following metadata:

| Field | Description |
|-------|-------------|
| `url` | Full URL of the crawled page |
| `page_title` | Text content of the `<title>` element |
| `depth` | Number of hops from the seed URL |
| `content_type` | MIME type of the response |
| `timestamp` | Crawl time in UTC RFC3339 format |

Example:
```json
{
  "url": "https://example.com/about",
  "page_title": "About Us",
  "depth": 1,
  "content_type": "text/html; charset=utf-8",
  "timestamp": "2026-03-27T17:26:34Z"
}
```

## Limitations

- Only the target domain and its subdomains are crawled; external links are skipped by design.
- No support for authenticated pages (login-gated content).
