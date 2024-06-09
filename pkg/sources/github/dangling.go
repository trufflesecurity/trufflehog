package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var danglingCommitsCache = simple.NewCache[struct{}]()

// TODO: Deduplicate deleted branches coming from pull requests.
func (s *Source) findDanglingCommits(ctx context.Context, owner string, repo string, commitsChan chan string) error {
	defer close(commitsChan)
	defer danglingCommitsCache.Clear()

	ctx.Logger().V(2).Info("Finding dangling commits created by force-pushes")
	if err := s.getRepoActivity(ctx, owner, repo, forcePush, commitsChan); err != nil {
		//return err
		ctx.Logger().Error(err, "Failed to retrieve force-push dangling commits")
	}

	ctx.Logger().V(2).Info("Finding dangling commits created by deleted branches")
	if err := s.getRepoActivity(ctx, owner, repo, branchDeletion, commitsChan); err != nil {
		//return err
		ctx.Logger().Error(err, "Failed to retrieve deleted branch dangling commits")
	}

	ctx.Logger().V(2).Info("Finding dangling commits created by pull request force-pushes")
	if err := s.getRepoPrForcePushes(ctx, owner, repo, commitsChan); err != nil {
		//return err
		ctx.Logger().Error(err, "Failed to retrieve all PR force pushes")
	}

	return nil
}

func handleCommit(ctx context.Context, commitsChan chan string, sha string) error {
	if sha == "" {
		return nil
	}

	if danglingCommitsCache.Exists(sha) {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case commitsChan <- sha:
			danglingCommitsCache.Set(sha, struct{}{})
			return nil
		default:
			ctx.Logger().V(4).Info("Dangling commits channel is at capacity. Sleeping until it's empty...", "capacity", cap(commitsChan))
			waitForChannelToEmpty(commitsChan)
		}
	}
}

// region Repository activity feed
type activityType int

const (
	forcePush activityType = iota
	branchDeletion
)

func (a activityType) String() string {
	return [...]string{"force_push", "branch_deletion"}[a]
}

type activityResponse struct {
	Payload activityPayload `json:"payload"`
}

type activityPayload struct {
	ActivityList activityListPayload `json:"activityList"`
}

type activityListPayload struct {
	Items       []activityListItem `json:"items"`
	HasNextPage bool               `json:"hasNextPage"`
	Cursor      string             `json:"cursor"`
}

type activityListItem struct {
	Before   string             `json:"before"`
	After    string             `json:"after"`
	Ref      string             `json:"ref"`
	PushedAt string             `json:"pushedAt"`
	PushType string             `json:"pushType"`
	Pusher   activityListPusher `json:"pusher"`
	Commit   activityListCommit `json:"commit"`
}

type activityListPusher struct {
	Login string `json:"login"`
}
type activityListCommit struct {
	Message string `json:"message"`
}

func getRandomDelay(min, max time.Duration) time.Duration {
	durationRange := max - min
	return min + time.Duration(rand.Int63n(int64(durationRange)))
}

func waitForChannelToEmpty(ch chan string) {
	for len(ch) > 0 {
		time.Sleep(1 * time.Second)
	}
}

// getRepoActivity retrieves the repository's enhanced activity history.
// e.g., https://github.com/trufflesecurity/trufflehog/activity
func (s *Source) getRepoActivity(ctx context.Context, owner string, name string, activityType activityType, commitsChan chan string) error {
	var (
		client = common.SaneHttpClient()
		// TODO: Don't hard-code `github.com`.
		repoUrl = fmt.Sprintf("https://github.com/%s/%s/activity", owner, name)
		cursor  string
	)

	for {
		ctx.Logger().V(4).Info("Getting repository activity", "type", activityType, "cursor", cursor)

		res, err := getRepoActivityPage(ctx, client, repoUrl, activityType, cursor)
		if err != nil {
			if errors.Is(err, rateLimitError) {
				continue
			}
			return err
		}

		activity := res.Payload.ActivityList
		for _, item := range activity.Items {
			if err := handleCommit(ctx, commitsChan, item.Before); err != nil {
				return err
			}
		}

		if !activity.HasNextPage {
			break
		}
		cursor = activity.Cursor

		// Generate a random duration within the specified range
		delay := getRandomDelay(250*time.Millisecond, 5*time.Second)
		ctx.Logger().V(1).Info("Sleeping until next iteration", "delay", delay.String())
		time.Sleep(delay)
	}

	return nil
}

var rateLimitError = errors.New("rate limit exceeded")

// getRepoActivityPage
func getRepoActivityPage(ctx context.Context, client *http.Client, repoUrl string, activityType activityType, cursor string) (*activityResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repoUrl, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("per_page", "100")
	q.Set("activity_type", activityType.String())
	if cursor != "" {
		q.Set("after", cursor)
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	body, _ := io.ReadAll(res.Body)

	switch res.StatusCode {
	case http.StatusOK:
		var aRes activityResponse
		if err := json.Unmarshal(body, &aRes); err != nil {
			return nil, err
		}

		return &aRes, nil
	case http.StatusTooManyRequests:
		var (
			retryAfter time.Duration
			jitter     = time.Duration(rand.Intn(10)+1) * time.Second
		)

		if v := res.Header.Get("Retry-After"); v != "" {
			seconds, _ := strconv.Atoi(v)
			retryAfter = time.Duration(seconds) * time.Second
		} else {
			ctx.Logger().Info("Unknown retry after")
			for header, values := range res.Header {
				ctx.Logger().Info("429 dangling commit header", "header", header, "values", values)
			}
			retryAfter = 5 * time.Minute
		}
		retryAfter += jitter

		ctx.Logger().Info("Exceeded rate-limit while fetching activity", "activity_type", activityType.String(), "retry_after", retryAfter.String())
		time.Sleep(retryAfter)
		return nil, rateLimitError
	default:
		for header, values := range res.Header {
			ctx.Logger().Info("unknown dangling commit header", "header", header, "values", values)
		}

		return nil, fmt.Errorf("unexpected status code %d: '%s'", res.StatusCode, string(body))
	}
}

//endregion

//region GraphQL Pull Request events

type (
	RateLimit struct {
		ResetAt   githubv4.DateTime
		Cost      githubv4.Int
		Remaining githubv4.Int
	}

	PullRequestFragment struct {
		TimeLineItems TimeLineItemFragment `graphql:"timelineItems(first: 100, after: $timelineCursor, itemTypes: [HEAD_REF_FORCE_PUSHED_EVENT])"`
	}

	TimeLineItemFragment struct {
		Nodes []struct {
			HeadRefForcePushedEventFragment `graphql:"... on HeadRefForcePushedEvent"`
		}
		PageInfo struct {
			HasNextPage bool
			EndCursor   githubv4.String
		}
	}

	HeadRefForcePushedEventFragment struct {
		BeforeCommit struct {
			CommitUrl string
			Oid       string
		}
	}
)

// getRepoPrForcePushes retrieves all `HeadRefForcePushedEvent`s from a repository's pull requests.
// Based on https://github.com/trufflesecurity/trufflehog/issues/2494#issuecomment-1960912861
func (s *Source) getRepoPrForcePushes(ctx context.Context, owner string, name string, commitsChan chan string) error {
	var q struct {
		RateLimit RateLimit

		Repository struct {
			PullRequests struct {
				Nodes []struct {
					Number              int
					PullRequestFragment `graphql:"... on PullRequest"`
				}
				PageInfo struct {
					HasNextPage bool
					EndCursor   githubv4.String
				}
			} `graphql:"pullRequests(first: 100, after: $pullRequestCursor)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	variables := map[string]interface{}{
		"owner": githubv4.String(owner),
		"name":  githubv4.String(name),
		// Null after argument to get first page.
		"pullRequestCursor": (*githubv4.String)(nil),
		"timelineCursor":    (*githubv4.String)(nil),
	}

	// Get comments from all pages.
	for {
		ctx.Logger().V(2).Info("Getting pull request force-pushes", "owner", owner, "name", name, "cursor", variables["pullRequestCursor"])

		err := s.connector.GraphQLClient().Query(ctx, &q, variables)
		if err != nil {
			if s.handleRateLimit(ctx, err) {
				continue
			}
			return err
		}

		for _, n1 := range q.Repository.PullRequests.Nodes {
			for _, n2 := range n1.TimeLineItems.Nodes {
				if err := handleCommit(ctx, commitsChan, n2.BeforeCommit.Oid); err != nil {
					return err
				}
			}

			// TODO: Enumerate `timelineCursor` separately from `pullRequestCursor`
			p := n1.TimeLineItems.PageInfo
			if p.HasNextPage {
				variables["timelineCursor"] = githubv4.NewString(p.EndCursor)
				continue
			} else {
				variables["timelineCursor"] = (*githubv4.String)(nil)
			}
		}

		if !q.Repository.PullRequests.PageInfo.HasNextPage {
			break
		}
		variables["pullRequestCursor"] = githubv4.NewString(q.Repository.PullRequests.PageInfo.EndCursor)
	}

	return nil
}

//endregion
