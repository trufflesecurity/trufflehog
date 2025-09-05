package github

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// processIssuesWithComments process github repo issues with comments using graphql API
func (s *Source) processIssuesWithComments(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	vars := map[string]any{
		owner:              githubv4.String(repoInfo.owner),
		repository:         githubv4.String(repoInfo.name),
		issuesPerPage:      githubv4.Int(defaultPagination),
		issuesPagination:   (*githubv4.String)(nil),
		commentsPerPage:    githubv4.Int(defaultPagination),
		commentsPagination: (*githubv4.String)(nil),
	}

	var totalIssues int

	// loop will continue as long as there are issues in the repository
	for {
		var query issuesWithComments
		err := s.connector.GraphQLClient().Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("error fetching issues: %w", err)
		}

		totalIssues += len(query.GetIssues())

		ctx.Logger().V(5).Info("Scanning Issues",
			"total_issues", len(query.GetIssues()))

		if err := s.chunkGraphqlIssues(ctx, repoInfo, query.Repository.Issues.Nodes, reporter); err != nil {
			return err
		}

		// process each issue comments
		for _, issue := range query.GetIssues() {
			ctx.Logger().V(5).Info("Scanning Issue Comments",
				"issue_id", issue.Number,
				"total_comments", len(issue.GetIssueComments()),
			)

			if err := s.chunkComments(ctx, repoInfo, issue.GetIssueComments(), reporter, cutoffTime); err != nil {
				return err
			}

			// if issue has more than 100 comments, we need to send another request for that specific issue to pull more comments
			for issue.Comments.PageInfo.HasNextPage {
				commentVars := map[string]any{
					owner:              githubv4.String(repoInfo.owner),
					repository:         githubv4.String(repoInfo.name),
					issueNumber:        githubv4.Int(issue.Number),
					commentsPerPage:    githubv4.Int(defaultPagination),
					commentsPagination: issue.Comments.PageInfo.EndCursor,
				}

				// request this issue more comments
				var commentsQuery singleIssueComments
				err := s.connector.GraphQLClient().Query(ctx, &commentsQuery, commentVars)
				if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
					continue
				}

				if err != nil {
					return fmt.Errorf("error fetching issue: %w", err)
				}

				ctx.Logger().V(5).Info("Scanning additional issue comments",
					"issue_id", issue.Number,
					"total_comments", len(commentsQuery.GetIssueComments()))

				if err := s.chunkComments(ctx, repoInfo, commentsQuery.GetIssueComments(), reporter, cutoffTime); err != nil {
					return err
				}

				// update page info for loop
				issue.Comments.PageInfo = commentsQuery.Repository.Issue.Comments.PageInfo
			}
		}

		// paginate issues
		if !query.Repository.Issues.PageInfo.HasNextPage {
			ctx.Logger().V(4).Info("Scanned all repository issues with comments", "total_issues_scanned", totalIssues)
			break
		}

		// update issues pagination to go to next page
		vars[issuesPagination] = githubv4.NewString(query.Repository.Issues.PageInfo.EndCursor)
	}

	return nil
}

// processPRWithComments process github repo pull requests with inline comments
func (s *Source) processPRWithComments(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	vars := map[string]any{
		owner:                 githubv4.String(repoInfo.owner),
		repository:            githubv4.String(repoInfo.name),
		pullRequestPerPage:    githubv4.Int(defaultPagination),
		pullRequestPagination: (*githubv4.String)(nil),
		commentsPerPage:       githubv4.Int(defaultPagination),
		commentsPagination:    (*githubv4.String)(nil),
	}

	var totalPRs int

	// continue loop as long as there are pull requests remaining
	for {
		var query pullRequestWithComments
		err := s.connector.GraphQLClient().Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("error fetching pull requests with comments: %w", err)
		}

		totalPRs += len(query.GetPullRequests())

		ctx.Logger().V(5).Info("Scanning pull requests",
			"total_pull_requests", len(query.GetPullRequests()))

		if err := s.chunkGraphqlPullRequests(ctx, repoInfo, query.GetPullRequests(), reporter); err != nil {
			return err
		}

		// process each pr comments
		for _, pr := range query.GetPullRequests() {
			ctx.Logger().V(5).Info("Scanning pull request comments",
				"pull_request_no", pr.Number,
				"total_comments", len(pr.Comments.Nodes))

			if err := s.chunkComments(ctx, repoInfo, pr.GetPRComments(), reporter, cutoffTime); err != nil {
				return err
			}

			// if a pull request has more than 100 comments - some interns pull request might endup here :)
			for pr.Comments.PageInfo.HasNextPage {
				// request this pull request more comments
				var commentQuery singlePRComments
				singlePRVars := map[string]any{
					owner:              githubv4.String(repoInfo.owner),
					repository:         githubv4.String(repoInfo.name),
					pullRequestNumber:  pr.Number,
					commentsPerPage:    githubv4.Int(defaultPagination),
					commentsPagination: pr.Comments.PageInfo.EndCursor,
				}

				err := s.connector.GraphQLClient().Query(ctx, &commentQuery, singlePRVars)
				if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
					continue
				}

				if err != nil {
					return fmt.Errorf("error fetching pull request with comments: %w", err)
				}

				ctx.Logger().V(5).Info("Scanning additional comments",
					"pull_request_no", pr.Number,
					"total_comments", len(commentQuery.GetPRComments()))

				if err := s.chunkComments(ctx, repoInfo, commentQuery.GetPRComments(), reporter, cutoffTime); err != nil {
					return err
				}

				// update pr.Comments.PageInfo so loop condition reflects new state
				pr.Comments.PageInfo = commentQuery.Repository.PullRequest.Comments.PageInfo
			}
		}

		// move to next page of PRs
		if !query.Repository.PullRequests.PageInfo.HasNextPage {
			ctx.Logger().V(4).Info("Scanned all repository pull requests with comments", "total_pullrequests_scanned", totalPRs)
			break
		}

		// update pull request pagination to go to next page
		vars[pullRequestPagination] = githubv4.NewString(query.Repository.PullRequests.PageInfo.EndCursor)
	}

	return nil
}

// processReviewThreads process github repo pull request review threads
func (s *Source) processReviewThreads(ctx context.Context, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	vars := map[string]any{
		owner:                 githubv4.String(repoInfo.owner),
		repository:            githubv4.String(repoInfo.name),
		pullRequestPerPage:    githubv4.Int(defaultPagination),
		pullRequestPagination: (*githubv4.String)(nil),
		threadPerPage:         githubv4.Int(defaultPagination),
		threadPagination:      (*githubv4.String)(nil),
	}

	var threadIDs = make([]string, 0)

	// continue as long as pull requests have threads
	for {
		var query prWithReviewThreadIDs
		err := s.connector.GraphQLClient().Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("error fetching pr thread reviews: %w", err)
		}

		// collect thread ids
		for _, pr := range query.GetMinimalPullRequests() {
			prThreadIDs := pr.ReviewThreads.GetThreadIDs()
			threadIDs = append(threadIDs, prThreadIDs...)
		}

		if !query.Repository.PullRequests.PageInfo.HasNextPage {
			ctx.Logger().V(4).Info("Pulled all repository PR's threads IDs")
			break
		}

		// update pull request pagination to go to next page
		vars[pullRequestPagination] = githubv4.NewString(query.Repository.PullRequests.PageInfo.EndCursor)
	}

	ctx.Logger().V(4).Info("Pulled all thread IDs", "total_threads", len(threadIDs))

	// if we got more than 0 threads unfortunately :( than we need to pull their comments in batches
	if len(threadIDs) > 0 {
		// process in batches of max 100
		for _, batch := range chunkIDs(threadIDs, 100) {
			ctx.Logger().V(5).Info("Processing Thread comments in Batches", "batch_length", len(batch))
			// fetch comments for the batch of threads
			if err := s.fetchThreadComments(ctx, batch, repoInfo, reporter, cutoffTime); err != nil {
				return fmt.Errorf("error fetching thread review comments: %w", err)
			}
		}
	}

	return nil
}

// fetchThreadComments process github repo pull request threads and their comments
func (s *Source) fetchThreadComments(ctx context.Context, threadIDs []string, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	// Process in batches of 100
	var query multiReviewThreadComments
	vars := map[string]any{
		"ids":              threadIDs,
		commentsPerPage:    githubv4.Int(defaultPagination),
		commentsPagination: (*githubv4.String)(nil),
	}

	if err := s.connector.GraphQLClient().Query(ctx, &query, vars); err != nil {
		return fmt.Errorf("multi-thread query failed: %w", err)
	}

	// process each thread in batch
	for _, thread := range query.GetThreads() {
		if err := s.chunkComments(ctx, repoInfo, thread.GetThreadComments(), reporter, cutoffTime); err != nil {
			return err
		}

		// if a thread has more than 100 comments :)
		for thread.Comments.PageInfo.HasNextPage {
			// request this thread more comments
			var query singleReviewThreadComments
			reviewThreadVars := map[string]any{
				threadID:           thread.ID,
				commentsPerPage:    githubv4.Int(defaultPagination),
				commentsPagination: (*githubv4.String)(nil),
			}

			if err := s.connector.GraphQLClient().Query(ctx, &query, reviewThreadVars); err != nil {
				return fmt.Errorf("single-thread query failed: %w", err)
			}

			node := query.Node
			if err := s.chunkComments(ctx, repoInfo, node.Comments.Nodes, reporter, cutoffTime); err != nil {
				return err
			}

			if !node.Comments.PageInfo.HasNextPage {
				break
			}

			// update thread comments pagination
			reviewThreadVars[commentsPagination] = &node.Comments.PageInfo.EndCursor
		}
	}

	return nil
}

// chunkIDs splits a slice of IDs into multiple chunks of at most `size` elements.
// For example, if you have 250 IDs and size=100, this will return
//
//	[][]string{
//	  {id0 ... id99},   // first 100
//	  {id100 ... id199},// next 100
//	  {id200 ... id249} // last 50
//	}
func chunkIDs(ids []string, size int) [][]string {
	var chunks [][]string
	for size < len(ids) {
		ids, chunks = ids[size:], append(chunks, ids[0:size:size])
	}
	return append(chunks, ids)
}

// handleRateLimitWithChunkReporter is a wrapper around handleRateLimit that includes chunk reporting
func (s *Source) handleGraphqlRateLimitWithChunkReporter(ctx context.Context, reporter sources.ChunkReporter, rl *rateLimit, errIn error) bool {
	return s.handleGraphQLRateLimit(ctx, rl, errIn, &chunkErrorReporter{reporter: reporter})
}

// handleGraphQLRateLimit inspects the rateLimit info returned in GraphQL queries.
func (s *Source) handleGraphQLRateLimit(ctx context.Context, rl *rateLimit, errIn error, reporters ...errorReporter) bool {
	// check global resume time first (in case another request already set it)
	rateLimitMu.RLock()
	resumeTime := rateLimitResumeTime
	rateLimitMu.RUnlock()

	// if resume time is not empty and is after current time, than put the request to sleep till that.
	if !resumeTime.IsZero() && time.Now().Before(resumeTime) {
		retryAfter := time.Until(resumeTime)
		time.Sleep(retryAfter)
		return true
	}

	var retryAfter time.Duration
	// if rate limit exceeded error happened, wait for 5 minute before trying again
	if errIn != nil && strings.Contains(errIn.Error(), "rate limit exceeded") {
		now := time.Now()

		rateLimitMu.Lock()
		rateLimitResumeTime = now.Add(1 * time.Minute)
		retryAfter = time.Until(rateLimitResumeTime)
		ctx.Logger().Info("GraphQL RATE_LIMITED error (fallback)",
			"retry_after", retryAfter.String())
		rateLimitMu.Unlock()
	} else if rl != nil {
		// if rate limit remaining is more than 3 continue using graphql api
		if rl.Remaining > 3 {
			return false
		}

		// === only reach here if error is nil and rate limit remaining is less than 3 (safety)
		now := time.Now()
		retryAfter = time.Until(rl.ResetAt)
		// never negative and enforce a sane minimum backoff (avoid thrashing with 1s/2s retries)
		if cmp.Less(retryAfter, 5*time.Second) {
			retryAfter = 5 * time.Second
		}

		jitter := time.Duration(rand.IntN(10)+1) * time.Second
		retryAfter += jitter

		// update global resume time
		rateLimitMu.Lock()
		rateLimitResumeTime = now.Add(retryAfter)
		ctx.Logger().Info("exceeded GraphQL rate limit",
			"retry_after", retryAfter.String(),
			"resume_time", rateLimitResumeTime.Format(time.RFC3339))
		rateLimitMu.Unlock()

		for _, reporter := range reporters {
			_ = reporter.Err(ctx, fmt.Errorf("exceeded GraphQL rate limit"))
		}
	}

	githubNumRateLimitEncountered.WithLabelValues(s.name).Inc()
	time.Sleep(retryAfter)
	githubSecondsSpentRateLimited.WithLabelValues(s.name).Add(retryAfter.Seconds())

	return true
}

func (s *Source) chunkGraphqlIssues(ctx context.Context, repoInfo repoInfo, issues []issue, reporter sources.ChunkReporter) error {
	for _, issue := range issues {
		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SourceType: s.Type(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(issue.URL),
						Username:   sanitizer.UTF8(issue.Author.Login),
						Repository: sanitizer.UTF8(repoInfo.fullName),
						Timestamp:  sanitizer.UTF8(issue.CreatedAt.String()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(issue.Title + "\n" + issue.Body)),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) chunkComments(ctx context.Context, repoInfo repoInfo, comments []comment, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	for _, comment := range comments {
		// Stop processing comments as soon as one created before the cutoff time is detected, as these are sorted
		if cutoffTime != nil && comment.UpdatedAt.Before(*cutoffTime) {
			continue
		}

		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			SourceType: s.Type(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(comment.URL),
						Username:   sanitizer.UTF8(comment.Author.Login),
						Repository: sanitizer.UTF8(repoInfo.fullName),
						Timestamp:  sanitizer.UTF8(comment.CreatedAt.String()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(comment.Body)),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) chunkGraphqlPullRequests(ctx context.Context, repoInfo repoInfo, prs []pullRequest, reporter sources.ChunkReporter) error {
	for _, pr := range prs {
		// Create chunk and send it to the channel.
		chunk := sources.Chunk{
			SourceName: s.name,
			SourceID:   s.SourceID(),
			SourceType: s.Type(),
			JobID:      s.JobID(),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:       sanitizer.UTF8(pr.URL),
						Username:   sanitizer.UTF8(pr.Author.Login),
						Repository: sanitizer.UTF8(repoInfo.fullName),
						Timestamp:  sanitizer.UTF8(pr.CreatedAt.String()),
						Visibility: repoInfo.visibility,
					},
				},
			},
			Data:   []byte(sanitizer.UTF8(pr.Title + "\n" + pr.Body)),
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}
