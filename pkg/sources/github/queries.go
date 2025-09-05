package github

import (
	"time"

	"github.com/shurcooL/githubv4"
)

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

// pullRequestWithComments represent a repository pull request nodes
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

// singlePRComments represents a single PR comments
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

// prWithReviewThreadIDs represents repository pull requests with review threads IDs
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

// minimalPullRequest represents a pull request with no and review threads
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

// singleReviewThreadComments fetches one review thread with comment pagination
type singleReviewThreadComments struct {
	Node struct {
		ID       string
		Comments commentNodes `graphql:"... on PullRequestReviewThread"`
	} `graphql:"node(id: $id)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// GetThreads returns all review thread nodes
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

// issuesWithComments represents a repository issues with comments
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

// issue represents a single PR issue
type issue struct {
	Number    int
	Title     string
	Body      string
	URL       string
	Author    author
	CreatedAt time.Time
	Comments  commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
}

// singleIssueComments represents a single PR issue with comments
type singleIssueComments struct {
	Repository struct {
		Issue struct {
			Comments commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"issue(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit
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

type author struct {
	Login string `graphql:"login"`
}

type pageInfo struct {
	HasNextPage bool            `graphql:"hasNextPage"`
	EndCursor   githubv4.String `graphql:"endCursor"`
}

type rateLimit struct {
	Remaining int       `graphql:"remaining"`
	ResetAt   time.Time `graphql:"resetAt"`
}
