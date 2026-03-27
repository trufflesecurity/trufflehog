# TruffleHog Web Source

The Web source enables TruffleHog to crawl and scan websites for secrets and sensitive information. It uses the Colly web scraper framework to systematically browse web pages and analyze their content for exposed credentials, API keys, private keys, and other secrets.

## Features

- **Web Crawling**: Automatically crawl websites starting from a seed URL
- **Robots.txt Compliance**: Respects website `robots.txt` rules for ethical crawling
- **Subdomain Support**: Crawls subdomains of the target domain
- **Customizable Delays**: Set delays between requests to avoid overwhelming servers
- **Metadata Extraction**: Captures page titles, URLs, content types, and timestamps
- **Error Handling**: Gracefully handles network errors and HTTP failures

## Configuration

### Required Parameters

- **`--url`**: One or more URLs to scan (required)
  - Supports both `http://` and `https://` URLs
  - Examples: `https://example.com` or `http://staging.app.com`
  - Can specify multiple URLs: `--url https://example.com --url https://app.com`

### Optional Parameters

- **`--crawl`**: Enable crawling to follow links discovered on pages (default: `false`)
  - `false`: Only scan the provided seed URL(s), don't follow links
  - `true`: Follow discovered links to scan additional pages
  - Useful for comprehensive scanning of entire websites

- **`--depth`**: Maximum link depth to follow when crawling (default: `1`)
  - `0`: Only scan the seed URL(s), no link following
  - `1`: Scan seed URL(s) + direct links from those pages
  - `2`: Scan seed + direct links + links from those pages (two levels deep)
  - `3+`: Continue following links up to the specified depth
  - Note: Deeper scans take longer and consume more resources

- **`--delay`**: Delay in seconds between requests to the same domain (default: `1`)
  - Recommended: 1-2 seconds for responsible, server-friendly scanning
  - Helps avoid overwhelming the target website
  - Respects `robots.txt` Crawl-delay directives when present

## Usage

### Command Line Examples

**Scan single URL only (no crawling)**
```bash
trufflehog web --url https://example.com
```

**Scan single URL with 1 level of link following**
```bash
trufflehog web --url https://example.com --crawl --depth 1 --delay 2
```

**Scan multiple URLs with deeper crawling**
```bash
trufflehog web \
  --url https://example.com \
  --url https://app.example.com \
  --crawl \
  --depth 2 \
  --delay 1
```

**Comprehensive website scan (2 levels deep, 2-second delays)**
```bash
trufflehog web --url https://mycompany.com --crawl --depth 2 --delay 2
```

## Behavior

### Domain Handling

- Crawls the exact domain provided (e.g., `example.com`)
- Crawls all subdomains (e.g., `www.example.com`, `mail.example.com`)
- Does NOT crawl other domains or external links

### Robots.txt Respect

By default, the crawler respects `robots.txt` files:
- Reads `robots.txt` from the website root
- Skips paths marked as disallowed
- Honors crawl-delay directives

To ignore `robots.txt` (not recommended), modify the code:
```go
collector.IgnoreRobotsTxt = true
```

### User Agent

The crawler identifies itself as:
```
trufflehog-web (+https://github.com/trufflesecurity/trufflehog)
```

This allows website administrators to identify TruffleHog requests in their logs.

## Example Scenarios

### Quick Scan - Check Single Page for Secrets

```bash
trufflehog web --url https://mycompany.com
```
- Scans only the homepage
- No link following
- 1 second delay between any requests

### Thorough Scan - Crawl Entire Website

```bash
trufflehog web \
  --url https://mycompany.com \
  --crawl \
  --depth 2 \
  --delay 2
```
- Starts from homepage
- Follows links up to 2 levels deep
- Respectful 2-second delays between requests

### Multi-Site Scan - Check Multiple URLs

```bash
trufflehog web \
  --url https://main.company.com \
  --url https://staging.company.com \
  --url https://api.company.com \
  --crawl \
  --depth 1 \
  --delay 1
```
- Scans 3 different URLs
- Follows direct links from each
- 1 second delay to keep scanning fast

## Best Practices

1. **Always Get Permission**: Only scan websites you own or have explicit permission to scan

2. **Start Conservative**: Begin with no crawling, then gradually increase depth if needed

3. **Use Appropriate Delays**: 
   - `--delay 1`: Good for most websites
   - `--delay 2`: Large or busy websites
   - `--delay 0.5`: Staging/internal websites only

4. **Respect Crawl Depth**: 
   - `--depth 0`: Just the seed URL (fastest, least coverage)
   - `--depth 1`: Seed + direct links (balanced)
   - `--depth 2+`: Comprehensive but slower and more resource-intensive

5. **Monitor Robot Rules**: Keep `robots.txt` respect enabled to honor website crawling guidelines

6. **Check Logs**: Review output to ensure scanning is working as expected

7. **Test First**: Test on staging environments before scanning production sites

## Output

The Web source emits chunks containing:

- **Page Content**: The raw HTML/text content of each page
- **Page Title**: Extracted from the `<title>` tag
- **URL**: The full URL of the crawled page
- **Depth**: How many links deep the page is from the seed URL
- **Content-Type**: The MIME type of the content (e.g., `text/html`)
- **Timestamp**: When the page was crawled (UTC, RFC3339 format)

### Example Metadata

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

- **Link Depth Only**: Maximum crawl depth is limited by the `--depth` flag
  - Deeper scans take longer and consume more memory
  - Very deep crawls (5+) on large websites may timeout or consume excessive resources

- **Single Domain**: Only crawls the target domain and its subdomains
  - External links are skipped by design
  - Run multiple scans for different domains

- **30-Second Timeout**: Hard limit on individual crawl operations
  - Adjust in code if needed: `context.WithTimeout(context.Background(), 30*time.Second)`

- **No JavaScript Rendering**: Static HTML content only
  - Websites with JavaScript-rendered content may appear incomplete
  - Future enhancement: Add JavaScript rendering support

- **No Authentication**: Cannot scan behind login pages
  - Workaround: Manually extract session cookies and pass them as headers
  - Future enhancement: Add authentication support

## Troubleshooting

### No Pages Crawled

Check for:
1. **Invalid URL**: Ensure the URL is valid and accessible
2. **Network Issues**: Verify internet connectivity
3. **Robots.txt Block**: The website's `robots.txt` may block all crawling
4. **No Discoverable Links**: The page may have no links for the crawler to follow

### Slow Crawling

- Increase `concurrency` (but be respectful)
- Reduce `delay` if appropriate
- Check your internet connection

## Security Considerations

- **Sensitive Data**: Be cautious when scanning internal or staging environments
- **Legal Compliance**: Ensure you have authorization before scanning websites
- **Network Traffic**: Crawling generates significant network traffic and server logs

## Future Enhancements

- [ ] JavaScript rendering support (Puppeteer/Playwright integration)
- [ ] Authentication support (Basic auth, cookies, form login)
- [ ] Custom header configuration
- [ ] Form submission and POST request handling
- [ ] Incremental crawling with state persistence
- [ ] Configurable timeout per scan
- [ ] Rate limiting by content size
- [ ] Proxy support for scanning through corporate networks

## References

- [Colly Web Scraping Framework](http://go-colly.org/)
- [Robots.txt Specification](https://en.wikipedia.org/wiki/Robots.txt)
- [Responsible Web Crawling Guidelines](https://www.robotstxt.org/)
