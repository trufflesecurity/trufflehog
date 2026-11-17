package github

import (
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

// This file scans issues, pull requests, and their comments through the GitHub
// GraphQL API. It is used instead of the REST listings when
// feature.UseGithubGraphQLAPI is on. GraphQL lets one request return a page of
// issues or PRs together with their first page of comments, so it needs far
// fewer requests than REST on busy repositories.
//
// Every listing follows the same pattern: send the query, let
// handleGraphQLRateLimit decide whether to retry it, fail on any other error,
// emit chunks, then follow pageInfo.endCursor until hasNextPage is false.

// processIssuesWithComments scans every issue in the repository: its title and
// body, and all of its comments. Issues come 100 per page with their first 100
// comments. An issue with more comments gets extra requests for the rest.
func (s *Source) processIssuesWithComments(
	ctx context.Context, graphqlClient *githubv4.Client, repoInfo repoInfo,
	reporter sources.ChunkReporter, cutoffTime *time.Time,
) error {
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
		err := graphqlClient.Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("error fetching issues: %w", err)
		}

		totalIssues += len(query.GetIssues())

		ctx.Logger().V(4).Info("Scanning Issues",
			"total_issues", len(query.GetIssues()))

		if err := s.chunkGraphqlIssues(ctx, repoInfo, query.Repository.Issues.Nodes, reporter); err != nil {
			return err
		}

		// process each issue comments
		for _, issue := range query.GetIssues() {
			ctx.Logger().V(3).Info("Scanning Issue Comments",
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
				err := graphqlClient.Query(ctx, &commentsQuery, commentVars)
				if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &commentsQuery.RateLimit, err) {
					continue
				}

				if err != nil {
					return fmt.Errorf("error fetching issue: %w", err)
				}

				ctx.Logger().V(4).Info("Scanning additional issue comments",
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

// processPRWithComments scans every pull request in the repository: its title
// and body, and all of its conversation comments. Review comments on code
// lines are not part of this query, processReviewThreads handles them.
func (s *Source) processPRWithComments(ctx context.Context, graphqlClient *githubv4.Client, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
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
		err := graphqlClient.Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("error fetching pull requests with comments: %w", err)
		}

		totalPRs += len(query.GetPullRequests())

		ctx.Logger().V(4).Info("Scanning pull requests",
			"total_pull_requests", len(query.GetPullRequests()))

		if err := s.chunkGraphqlPullRequests(ctx, repoInfo, query.GetPullRequests(), reporter); err != nil {
			return err
		}

		// process each pr comments
		for _, pr := range query.GetPullRequests() {
			ctx.Logger().V(3).Info("Scanning pull request comments",
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
					pullRequestNumber:  githubv4.Int(pr.Number),
					commentsPerPage:    githubv4.Int(defaultPagination),
					commentsPagination: pr.Comments.PageInfo.EndCursor,
				}

				err := graphqlClient.Query(ctx, &commentQuery, singlePRVars)
				if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &commentQuery.RateLimit, err) {
					continue
				}

				if err != nil {
					return fmt.Errorf("error fetching pull request with comments: %w", err)
				}

				ctx.Logger().V(4).Info("Scanning additional comments",
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

// processReviewThreads scans review comments, the comments left on code lines
// of a pull request. It works in two steps to stay under GitHub's node limit:
// first it walks all PRs and collects their review thread IDs, then it fetches
// the comments of those threads by ID, 100 threads per request.
func (s *Source) processReviewThreads(ctx context.Context, graphqlClient *githubv4.Client, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
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
		err := graphqlClient.Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("error fetching pr thread reviews: %w", err)
		}

		// collect thread ids
		for _, pr := range query.GetMinimalPullRequests() {
			threadIDs = append(threadIDs, pr.ReviewThreads.GetThreadIDs()...)

			// the query above only returns the first 100 threads of each PR
			if pr.ReviewThreads.PageInfo.HasNextPage {
				moreIDs, err := s.fetchMoreThreadIDs(ctx, graphqlClient, repoInfo, pr.Number, pr.ReviewThreads.PageInfo, reporter)
				if err != nil {
					return err
				}
				threadIDs = append(threadIDs, moreIDs...)
			}
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
			ctx.Logger().V(4).Info("Processing Thread comments in Batches", "batch_length", len(batch))
			// fetch comments for the batch of threads
			if err := s.fetchThreadComments(ctx, graphqlClient, batch, repoInfo, reporter, cutoffTime); err != nil {
				return fmt.Errorf("error fetching thread review comments: %w", err)
			}
		}
	}

	return nil
}

// fetchMoreThreadIDs returns the review thread IDs of one pull request that
// come after pageInfo, for PRs with more threads than fit in the first page.
func (s *Source) fetchMoreThreadIDs(ctx context.Context, graphqlClient *githubv4.Client, repoInfo repoInfo, prNumber int, pageInfo pageInfo, reporter sources.ChunkReporter) ([]string, error) {
	vars := map[string]any{
		owner:             githubv4.String(repoInfo.owner),
		repository:        githubv4.String(repoInfo.name),
		pullRequestNumber: githubv4.Int(prNumber),
		threadPerPage:     githubv4.Int(defaultPagination),
	}

	var threadIDs []string
	for pageInfo.HasNextPage {
		vars[threadPagination] = pageInfo.EndCursor

		var query singlePRReviewThreadIDs
		err := graphqlClient.Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("error fetching review threads of pull request %d: %w", prNumber, err)
		}

		threads := query.Repository.PullRequest.ReviewThreads
		threadIDs = append(threadIDs, threads.GetThreadIDs()...)
		pageInfo = threads.PageInfo
	}

	ctx.Logger().V(4).Info("Pulled additional thread IDs", "pull_request_no", prNumber, "total_threads", len(threadIDs))

	return threadIDs, nil
}

// fetchThreadComments scans the comments of one batch of review threads (at
// most 100 IDs). A thread with more than 100 comments gets extra requests for
// the rest.
func (s *Source) fetchThreadComments(ctx context.Context, graphqlClient *githubv4.Client, threadIDs []string, repoInfo repoInfo, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	vars := map[string]any{
		"ids":              threadIDs,
		commentsPerPage:    githubv4.Int(defaultPagination),
		commentsPagination: (*githubv4.String)(nil),
	}

	var query multiReviewThreadComments
	for {
		// reset so a retry does not decode on top of a half filled response
		query = multiReviewThreadComments{}
		err := graphqlClient.Query(ctx, &query, vars)
		if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &query.RateLimit, err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("multi-thread query failed: %w", err)
		}

		break
	}

	// process each thread in batch
	for _, thread := range query.GetThreads() {
		if err := s.chunkComments(ctx, repoInfo, thread.GetThreadComments(), reporter, cutoffTime); err != nil {
			return err
		}

		// if a thread has more than 100 comments, page through the rest of them
		pageInfo := thread.Comments.PageInfo
		threadVars := map[string]any{
			threadID:        thread.ID,
			commentsPerPage: githubv4.Int(defaultPagination),
		}

		for pageInfo.HasNextPage {
			threadVars[commentsPagination] = pageInfo.EndCursor

			var threadQuery singleReviewThreadComments
			err := graphqlClient.Query(ctx, &threadQuery, threadVars)
			if s.handleGraphqlRateLimitWithChunkReporter(ctx, reporter, &threadQuery.RateLimit, err) {
				continue
			}

			if err != nil {
				return fmt.Errorf("single-thread query failed: %w", err)
			}

			comments := threadQuery.Node.PullRequestReviewThread.Comments
			if err := s.chunkComments(ctx, repoInfo, comments.Nodes, reporter, cutoffTime); err != nil {
				return err
			}

			pageInfo = comments.PageInfo
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

// graphqlMinRemaining is how much GraphQL quota we keep in reserve. When a
// query leaves this much or less, we wait for the quota to reset.
const graphqlMinRemaining = 3

// handleGraphqlRateLimitWithChunkReporter is a wrapper around handleGraphQLRateLimit that includes chunk reporting
func (s *Source) handleGraphqlRateLimitWithChunkReporter(
	ctx context.Context, reporter sources.ChunkReporter,
	rl *rateLimit, errIn error,
) bool {
	return s.handleGraphQLRateLimit(ctx, rl, errIn, &chunkErrorReporter{reporter: reporter})
}

// handleGraphQLRateLimit is called after every GraphQL query with the query's
// rateLimit and error. It returns true when the caller should send the same
// query again.
//
//   - errIn is a rate limit error: wait, then return true to retry.
//   - errIn is any other error: return false right away, so the caller fails
//     instead of retrying something that will never work.
//   - errIn is nil but the quota is almost used up: wait for the reset, then
//     return false so the caller keeps the result it already has.
//
// The resume time is shared with the REST handler and with other workers, so
// one worker hitting the limit makes the others wait too. If ctx is canceled
// during the wait, it returns false and the caller reports errIn.
func (s *Source) handleGraphQLRateLimit(ctx context.Context, rl *rateLimit, errIn error, reporters ...errorReporter) bool {
	var wait time.Duration
	switch {
	case errIn != nil:
		if !isGraphQLRateLimitErr(errIn) {
			return false
		}
		// the error does not say when the limit resets. GitHub asks to wait
		// at least a minute before retrying after a secondary rate limit.
		wait = time.Minute
	case rl.Remaining <= graphqlMinRemaining:
		// ResetAt can already be in the past, so keep a minimum wait to avoid
		// sending a burst of requests right at the reset.
		wait = max(time.Until(rl.ResetAt), 5*time.Second)
	}

	if wait > 0 {
		jitter := time.Duration(rand.IntN(10)+1) * time.Second
		wait += jitter

		rateLimitMu.Lock()
		if resume := time.Now().Add(wait); resume.After(rateLimitResumeTime) {
			rateLimitResumeTime = resume
		}
		ctx.Logger().Info("exceeded GraphQL rate limit",
			"retry_after", wait.String(),
			"resume_time", rateLimitResumeTime.Format(time.RFC3339))
		rateLimitMu.Unlock()

		for _, reporter := range reporters {
			_ = reporter.Err(ctx, fmt.Errorf("exceeded GraphQL rate limit"))
		}
	}

	// wait for our own limit, or one another worker hit, whichever ends later
	rateLimitMu.RLock()
	retryAfter := time.Until(rateLimitResumeTime)
	rateLimitMu.RUnlock()
	if retryAfter <= 0 {
		return false
	}

	githubNumRateLimitEncountered.WithLabelValues(s.name).Inc()
	slept, canceled := sleepWithContext(ctx, retryAfter)
	githubSecondsSpentRateLimited.WithLabelValues(s.name).Add(slept.Seconds())

	return errIn != nil && !canceled
}

// isGraphQLRateLimitErr reports whether err is GitHub refusing a query because
// we sent too many. githubv4 has no typed error for this, only text. GitHub
// says "rate limit" in every form we know of: the primary limit ("API rate
// limit exceeded for user ID ...") and the secondary limit ("You have exceeded
// a secondary rate limit"), sent either as a GraphQL error or as the body of a
// non-200 response.
func isGraphQLRateLimitErr(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "rate limit")
}

// chunkGraphqlIssues emits one chunk per issue with its title and body.
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
			Data:         []byte(sanitizer.UTF8(issue.Title + "\n" + issue.Body)),
			SourceVerify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

// chunkComments emits one chunk per comment, skipping comments last updated
// before cutoffTime when one is set.
func (s *Source) chunkComments(ctx context.Context, repoInfo repoInfo, comments []comment, reporter sources.ChunkReporter, cutoffTime *time.Time) error {
	for _, comment := range comments {
		// not every query sorts comments by update time, so skip old ones
		// instead of stopping at the first
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
			Data:         []byte(sanitizer.UTF8(comment.Body)),
			SourceVerify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

// chunkGraphqlPullRequests emits one chunk per pull request with its title and body.
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
			Data:         []byte(sanitizer.UTF8(pr.Title + "\n" + pr.Body)),
			SourceVerify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}
