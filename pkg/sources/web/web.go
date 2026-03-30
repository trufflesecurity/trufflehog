package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
	"golang.org/x/net/html"
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
		s.conn.UserAgent = "trufflehog-web (+https://github.com/trufflesecurity/trufflehog)"
	}

	if s.conn.GetIgnoreRobots() {
		ctx.Logger().Info("Warning: Robots.txt is ignored. Only use this if you have permission to crawl the target site.")
	}

	// validations
	if len(s.conn.GetUrls()) == 0 {
		return errors.New("no URL provided")
	}
	// TODO: Enable support for more than one URLs
	if len(s.conn.GetUrls()) > 1 {
		return errors.New("only one base URL is allowed right now")
	}

	// Validate URLs format
	for _, u := range s.conn.GetUrls() {
		if _, err := url.Parse(u); err != nil {
			return fmt.Errorf("invalid URL %q: %w", u, err)
		}
	}

	// TODO: reset metrics if needed

	return nil
}

// Chunks emits data over a channel that is decoded and scanned for secrets.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	var wg sync.WaitGroup

	// Create a background context for crawling (independent of incoming ctx)
	crawlCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, url := range s.conn.GetUrls() {
		ctx.Logger().V(5).Info("Processing Url", "url", url)
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			s.crawlURL(crawlCtx, url, chunksChan)
		}(url)
	}

	// Block until all crawls complete
	wg.Wait()
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

	url, err := url.Parse(seedURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", seedURL, err)
	}

	collector := colly.NewCollector(
		colly.UserAgent(s.conn.GetUserAgent()),
		colly.AllowedDomains(url.Hostname(), fmt.Sprintf("*.%s", url.Hostname())), // with subdomains
		colly.Async(true),
	)

	// By default, the crawler respects robots.txt rules. Setting IgnoreRobotsTxt to true overrides this behavior.
	// Users can enable this only when they have explicit permission to crawl the site.
	collector.IgnoreRobotsTxt = s.conn.GetIgnoreRobots()

	collector.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: s.concurrency,
		Delay:       time.Duration(s.conn.GetDelay()) * time.Second,
	})

	// Set up callbacks
	collector.OnResponse(func(r *colly.Response) {
		ctx.Logger().Info("Response recieved")
		if err := s.processChunk(ctx, r, chunksChan); err != nil {
			ctx.Logger().Error(err, "error processing page")
		}
	})
	collector.OnError(func(r *colly.Response, err error) {
		ctx.Logger().Error(err, "error fetching page", "url", r.Request.URL)
	})

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

func extractPageTitle(body []byte) string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	var title string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			title = strings.TrimSpace(n.FirstChild.Data)
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return title
}
