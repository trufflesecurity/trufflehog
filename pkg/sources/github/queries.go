package github

import (
	"time"

	"github.com/shurcooL/githubv4"
)

// This file holds the GraphQL query types used when UseGithubGraphQLAPI is on.
// The githubv4 library builds each query from the struct shape and tags, and
// fills the struct from the response. Variables like $first or $commentsAfter
// are passed as a map keyed by the constants below. The library takes each
// variable's GraphQL type from the Go type of its value, so numbers must be
// githubv4.Int (a plain int becomes the invalid type "int!") and cursors
// githubv4.String or *githubv4.String (nil pointer means "first page").
// Every query also asks for rateLimit so we can slow down before hitting it.

const (
	// query variable keys
	owner      = "owner"
	repository = "repo"

	pullRequestNumber     = "number"
	pullRequestPerPage    = "first"
	pullRequestPagination = "after"

	commentsPerPage    = "commentsFirst"
	commentsPagination = "commentsAfter"

	threadID         = "threadID"
	threadPerPage    = "threadsFirst"
	threadPagination = "threadsAfter"

	issueNumber      = "number"
	issuesPerPage    = "issuesFirst"
	issuesPagination = "issuesAfter"
)

// === Pull Requests with Comments ===

// pullRequestWithComments fetches one page of a repository's pull requests,
// each with the first page of its conversation comments. Review comments
// (comments on code lines) live in review threads and are fetched separately.
type pullRequestWithComments struct {
	Repository struct {
		PullRequests pullRequestNodes `graphql:"pullRequests(first: $first, after: $after, orderBy: {field: UPDATED_AT, direction: DESC})"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// pullRequestNodes represents a paginated list of pull requests
type pullRequestNodes struct {
	Nodes    []pullRequest
	PageInfo pageInfo
}

// pullRequest represents a single pull request with comment nodes
type pullRequest struct {
	Title     string
	Number    int
	URL       string
	Author    author
	CreatedAt time.Time
	Body      string
	Comments  commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter, orderBy: {field: UPDATED_AT, direction: DESC})"`
}

// commentNodes represents a paginated list of comments
type commentNodes struct {
	Nodes    []comment
	PageInfo pageInfo
}

// comment represents a single comment
type comment struct {
	Body      string
	CreatedAt time.Time
	UpdatedAt time.Time
	Author    author
	URL       string
}

// singlePRComments fetches the next page of conversation comments for one
// pull request. Used when a PR has more comments than fit in the first page.
type singlePRComments struct {
	Repository struct {
		PullRequest struct {
			Comments commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter, orderBy: {field: UPDATED_AT, direction: DESC})"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// GetPullRequests return list of pull requests
func (p pullRequestWithComments) GetPullRequests() []pullRequest {
	return p.Repository.PullRequests.Nodes
}

// GetPRComments return list of comments of the PR
func (p pullRequest) GetPRComments() []comment {
	return p.Comments.Nodes
}

// GetPRComments return list of comments of the PR
func (p singlePRComments) GetPRComments() []comment {
	return p.Repository.PullRequest.Comments.Nodes
}

// === Pull Request Review Threads IDs ===

// prWithReviewThreadIDs fetches one page of pull requests with only the IDs
// of their review threads. Thread comments are fetched later by ID, in
// batches, because nesting PRs > threads > comments in one query would hit
// GitHub's node limit fast.
type prWithReviewThreadIDs struct {
	Repository struct {
		PullRequests minimalPullRequestNodes `graphql:"pullRequests(first: $first, after: $after, orderBy: {field: UPDATED_AT, direction: DESC})"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// minimalPullRequestNodes represents a paginated list of pull request
type minimalPullRequestNodes struct {
	Nodes    []minimalPullRequest
	PageInfo pageInfo
}

// minimalPullRequest is a pull request number with the first page of its
// review thread IDs.
type minimalPullRequest struct {
	Number        int
	ReviewThreads reviewThreadIDNodes `graphql:"reviewThreads(first: $threadsFirst, after: $threadsAfter)"`
}

// reviewThreadIDNodes represents a paginated list of pr review threads
type reviewThreadIDNodes struct {
	Nodes    []reviewThreadID
	PageInfo pageInfo
}

// reviewThreadID represents a single review thread with ID
type reviewThreadID struct {
	ID string
}

func (p prWithReviewThreadIDs) GetMinimalPullRequests() []minimalPullRequest {
	return p.Repository.PullRequests.Nodes
}

// singlePRReviewThreadIDs fetches the next page of review thread IDs for one
// pull request. Used when a PR has more threads than fit in the first page.
type singlePRReviewThreadIDs struct {
	Repository struct {
		PullRequest struct {
			ReviewThreads reviewThreadIDNodes `graphql:"reviewThreads(first: $threadsFirst, after: $threadsAfter)"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

func (r reviewThreadIDNodes) GetThreadIDs() []string {
	var ids = make([]string, 0)

	for _, id := range r.Nodes {
		ids = append(ids, id.ID)
	}

	return ids
}

// === Review Threads with comments ===

// multiReviewThreadComments fetches multiple review threads (by IDs) and the first page of their comments.
type multiReviewThreadComments struct {
	Nodes []struct {
		PullRequestReviewThread reviewThreadComments `graphql:"... on PullRequestReviewThread"`
	} `graphql:"nodes(ids: $ids)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// reviewThreadComments represents a single thread and its comments.
type reviewThreadComments struct {
	ID       string
	Comments commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
}

// singleReviewThreadComments fetches the next page of comments for one review
// thread. node(id:) returns the generic Node interface, so the comments field
// has to be read through an inline fragment on PullRequestReviewThread.
type singleReviewThreadComments struct {
	Node struct {
		PullRequestReviewThread struct {
			Comments commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"... on PullRequestReviewThread"`
	} `graphql:"node(id: $threadID)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// GetThreads returns the threads in the batch. Nodes that are not review
// threads (for example an ID that no longer exists) come back empty and are
// dropped.
func (r multiReviewThreadComments) GetThreads() []reviewThreadComments {
	threads := make([]reviewThreadComments, 0)
	for _, n := range r.Nodes {
		if n.PullRequestReviewThread.ID != "" {
			threads = append(threads, n.PullRequestReviewThread)
		}
	}

	return threads
}

func (r reviewThreadComments) GetThreadComments() []comment {
	return r.Comments.Nodes
}

// === Issues with comments ===

// issuesWithComments fetches one page of a repository's issues, each with the
// first page of its comments. GraphQL issues never include pull requests.
type issuesWithComments struct {
	Repository struct {
		Issues issueNodes `graphql:"issues(first: $issuesFirst, after: $issuesAfter, orderBy: {field: UPDATED_AT, direction: DESC})"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// issueNodes represents a paginated list of issues
type issueNodes struct {
	Nodes    []issue
	PageInfo pageInfo
}

// issue represents a single issue
type issue struct {
	Number    int
	Title     string
	Body      string
	URL       string
	Author    author
	CreatedAt time.Time
	Comments  commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
}

// singleIssueComments fetches the next page of comments for one issue. Used
// when an issue has more comments than fit in the first page.
type singleIssueComments struct {
	Repository struct {
		Issue struct {
			Comments commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"issue(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

func (i issuesWithComments) GetIssues() []issue {
	return i.Repository.Issues.Nodes
}

func (i issue) GetIssueComments() []comment {
	return i.Comments.Nodes
}

func (i singleIssueComments) GetIssueComments() []comment {
	return i.Repository.Issue.Comments.Nodes
}

// === Others ===

// author is the user, bot, or app that wrote an issue, PR, or comment. For
// bots GraphQL returns the plain login ("dependabot") while REST adds a suffix
// ("dependabot[bot]"). Both name the same account, so we keep the login as is.
// Author is empty when the account was deleted.
type author struct {
	Login string `graphql:"login"`
}

// pageInfo tells whether another page exists and the cursor to request it.
type pageInfo struct {
	HasNextPage bool            `graphql:"hasNextPage"`
	EndCursor   githubv4.String `graphql:"endCursor"`
}

// rateLimit is the caller's GraphQL quota after the query ran. Only filled in
// when the query succeeds.
type rateLimit struct {
	Remaining int       `graphql:"remaining"`
	ResetAt   time.Time `graphql:"resetAt"`
}
