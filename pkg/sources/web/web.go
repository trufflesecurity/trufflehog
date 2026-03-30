package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
	"golang.org/x/net/html"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_WEB

type Source struct {
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	concurrency int
	conn        sourcespb.Web

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType { return SourceType }
func (s *Source) SourceID() sources.SourceID { return s.sourceId }
func (s *Source) JobID() sources.JobID       { return s.jobId }

// Init initializes the source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID,
	verify bool, connection *anypb.Any, concurrency int,
) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.concurrency = concurrency
	// If s.concurrency is 0, use 1
	// TODO: make it configurable
	if s.concurrency == 0 {
		s.concurrency = 1
	}

	if err := anypb.UnmarshalTo(connection, &s.conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	// Use the user-provided User-Agent if set; otherwise fall back to a default that identifies TruffleHog.
	if s.conn.GetUserAgent() == "" {
		ctx.Logger().Info("No user agent set; using default", "user-agent", "trufflehog-web (+https://github.com/trufflesecurity/trufflehog)")
		s.conn.UserAgent = "trufflehog-web (+https://github.com/trufflesecurity/trufflehog)"
	}

	// The 30-second timeout is a safety net
	if s.conn.GetTimeout() <= 0 {
		s.conn.Timeout = 30
	}

	if s.conn.GetIgnoreRobots() {
		ctx.Logger().Info("Warning: Robots.txt is ignored. Only use this if you have permission to crawl the target site.")
	}

	// validations
	if len(s.conn.GetUrls()) == 0 {
		return errors.New("no URL provided")
	}

	// Validate URLs format
	for _, u := range s.conn.GetUrls() {
		if _, err := url.Parse(u); err != nil {
			return fmt.Errorf("invalid URL %q: %w", u, err)
		}
	}

	// metrics
	jobIDStr := fmt.Sprint(s.jobId)
	webUrlsScanned.WithLabelValues(s.name, jobIDStr).Set(0)

	return nil
}

// Chunks emits data over a channel that is decoded and scanned for secrets.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	jobIDStr := fmt.Sprint(s.jobId)

	// Create a new context with timeout.
	crawlCtx, cancel := context.WithTimeout(ctx, time.Duration(s.conn.GetTimeout())*time.Second)
	defer cancel()

	eg, _ := errgroup.WithContext(crawlCtx)

	for _, u := range s.conn.GetUrls() {
		ctx.Logger().V(5).Info("Processing Url", "url", u)
		webUrlsScanned.WithLabelValues(s.name, jobIDStr).Inc()
		eg.Go(func() error {
			return s.crawlURL(crawlCtx, u, chunksChan)
		})
	}

	if err := eg.Wait(); err != nil {
		ctx.Logger().Error(err, "One or more crawls failed")
		return err
	}

	ctx.Logger().Info("All crawls completed")
	return nil
}

func (s *Source) crawlURL(ctx context.Context, seedURL string, chunksChan chan *sources.Chunk) error {
	// Add static crawl configuration to the context so that all subsequent logs include these fields.
	ctx = context.WithValues(ctx,
		"url", seedURL,
		"user_agent", s.conn.GetUserAgent(),
		"ignore_robots", s.conn.GetIgnoreRobots(),
	)

	parsedURL, err := url.Parse(seedURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", seedURL, err)
	}

	// docs: http://go-colly.org/docs/introduction/configuration/
	collector := colly.NewCollector(
		colly.UserAgent(s.conn.GetUserAgent()),
		colly.Async(true),
	)

	// Apply depth limit only when crawling is enabled and a positive depth is set.
	if s.conn.GetCrawl() && s.conn.GetDepth() > 0 {
		collector.MaxDepth = int(s.conn.GetDepth())
	}

	// By default, the crawler respects robots.txt rules. Setting IgnoreRobotsTxt to true overrides this behavior.
	// Users can enable this only when they have explicit permission to crawl the target site.
	collector.IgnoreRobotsTxt = s.conn.GetIgnoreRobots()

	if err := collector.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: s.concurrency,
		Delay:       time.Duration(s.conn.GetDelay()) * time.Second,
	}); err != nil {
		return fmt.Errorf("failed to limit rules to the colly collector: %w", err)
	}

	// request validations
	collector.OnRequest(func(r *colly.Request) {
		host := r.URL.Hostname()
		if host != parsedURL.Hostname() && !strings.HasSuffix(host, parsedURL.Hostname()) {
			ctx.Logger().V(5).Info("blocked by domain filter", "url", r.URL.String())
			r.Abort()
		}
	})

	// Set up callbacks
	collector.OnResponse(func(r *colly.Response) {
		ctx.Logger().Info("Response received")
		if err := s.processChunk(ctx, r, chunksChan); err != nil {
			ctx.Logger().Error(err, "error processing page")
		}
	})
	collector.OnError(func(r *colly.Response, err error) {
		ctx.Logger().Error(err, "error fetching page", "url", r.Request.URL)
	})

	// Follow links only when crawling is explicitly enabled.
	if s.conn.GetCrawl() {
		collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
			link := e.Request.AbsoluteURL(e.Attr("href"))
			if link == "" {
				return
			}

			if err := e.Request.Visit(link); err != nil {
				if _, ok := err.(*colly.AlreadyVisitedError); !ok {
					ctx.Logger().V(5).Info("Skipping link", "url", link, "reason", err)
				}
			}
		})

		// Also enqueue linked JavaScript files - a common location for hardcoded secrets.
		collector.OnHTML("script[src]", func(e *colly.HTMLElement) {
			src := e.Request.AbsoluteURL(e.Attr("src"))
			if src == "" {
				return
			}

			if err := e.Request.Visit(src); err != nil {
				if _, ok := err.(*colly.AlreadyVisitedError); !ok {
					ctx.Logger().V(5).Info("Skipping script", "url", src, "reason", err)
				}
			}
		})
	}

	// Create a channel to signal when the crawl is done.
	done := make(chan struct{})
	go func() {
		ctx.Logger().Info("Starting crawl")
		if err := collector.Visit(seedURL); err != nil {
			ctx.Logger().Error(err, "Visit failed")
		}
		collector.Wait() // blocks until all requests finish
		close(done)
	}()

	// Wait for either crawl to finish or context cancellation.
	select {
	case <-done:
		ctx.Logger().Info("Crawl finished normally")
		return nil
	case <-ctx.Done():
		ctx.Logger().Info("Context cancelled or timeout reached")
		<-done // Wait for goroutine to finish cleanup
		return ctx.Err()
	}
}

func (s *Source) processChunk(ctx context.Context, data *colly.Response, chunksChan chan *sources.Chunk) error {
	pageTitle := extractPageTitle(data.Body)

	ctx.Logger().V(5).WithValues("page_title", pageTitle).Info("Processing web chunk")

	// Create a chunk from the response body.
	chunk := &sources.Chunk{
		Data:         data.Body,
		SourceType:   s.Type(),
		SourceName:   s.name,
		SourceID:     s.SourceID(),
		JobID:        s.JobID(),
		SourceVerify: s.verify,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Web{
				Web: &source_metadatapb.Web{
					Url:         data.Request.URL.String(),
					PageTitle:   pageTitle,
					Depth:       int64(data.Request.Depth),
					ContentType: data.Headers.Get("Content-Type"),
					Timestamp:   time.Now().UTC().Format(time.RFC3339),
				},
			},
		},
	}

	return common.CancellableWrite(ctx, chunksChan, chunk)
}

// extractPageTitle parses an HTML document and returns the text content of the
// first <title> element, with leading and trailing whitespace trimmed.
// Returns an empty string if the body is empty, cannot be parsed, or contains
// no <title> element.
func extractPageTitle(body []byte) string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ""
	}

	var title string

	// f is a recursive depth-first walker over the HTML node tree.
	// It is declared as a variable first so that the closure can reference
	// itself when recursing into child nodes.
	var f func(*html.Node)
	f = func(n *html.Node) {
		if title != "" {
			return // already found, skip the rest of the tree
		}
		// We are only interested in element nodes (e.g. <title>, <div>).
		// Text, comment, and doctype nodes are skipped by this check.
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			// <title> content is always a single text node directly inside
			// the element. n.FirstChild.Data holds the raw string value.
			title = strings.TrimSpace(n.FirstChild.Data)
			return
		}

		// Recurse into child nodes to continue the depth-first traversal.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return title
}
