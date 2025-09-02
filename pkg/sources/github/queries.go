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

// === Pull Request Review Threads and Comments ===

// prWithReviewComments represents repository pull requests with review threads
type prWithReviewComments struct {
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
	ReviewThreads reviewThreadNodes `graphql:"reviewThreads(first: $threadsFirst, after: $threadsAfter)"`
}

// reviewThreadNodes represents a paginated list of pr review threads
type reviewThreadNodes struct {
	Nodes    []reviewThread
	PageInfo pageInfo
}

// reviewThread represents a single review thread with comment nodes
type reviewThread struct {
	ID       string
	Comments commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
}

type singlePullRequestThreads struct {
	Repository struct {
		PullRequest struct {
			ReviewThreads struct {
				Nodes    []reviewThread
				PageInfo pageInfo
			} `graphql:"reviewThreads(first: $threadsFirst, after: $threadsAfter)"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

// singleReviewThreadComments represents a single review threads comments
type singleReviewThreadComments struct {
	Repository struct {
		PullRequest struct {
			ReviewThread struct {
				Comments commentNodes `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
			} `graphql:"reviewThread(id: $threadID)"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit rateLimit `graphql:"rateLimit"`
}

func (p prWithReviewComments) GetMinimalPullRequests() []minimalPullRequest {
	return p.Repository.PullRequests.Nodes
}

func (p minimalPullRequest) GetReviewThreads() []reviewThread {
	return p.ReviewThreads.Nodes
}

func (r reviewThread) GetThreadComments() []comment {
	return r.Comments.Nodes
}

func (r singleReviewThreadComments) GetThreadComments() []comment {
	return r.Repository.PullRequest.ReviewThread.Comments.Nodes
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
