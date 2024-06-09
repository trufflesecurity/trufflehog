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
	"unsafe"

	"github.com/shurcooL/githubv4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var danglingCommitsCache = memory.New[struct{}]()

type danglingCommit1 struct {
	Type activityType
	Sha  string
}

type danglingCommit2 struct {
	Sha  string
	Type activityType
}

func init() {
	d1 := danglingCommit1{}
	d2 := danglingCommit2{}
	fmt.Println("Size of danglingCommit1:", unsafe.Sizeof(d1))
	fmt.Println("Size of danglingCommit2:", unsafe.Sizeof(d2))
}

// TODO: Deduplicate deleted branches coming from pull requests.
func (s *Source) findDanglingCommits(ctx context.Context, owner string, repo string, commitsChan chan string) error {
	defer close(commitsChan)
	defer danglingCommitsCache.Clear()

	if err := s.getRepoPrForcePushes(ctx, owner, repo, commitsChan); err != nil {
		//return err
		ctx.Logger().Error(err, "Failed to retrieve all PR force pushes")
	} else {
		ctx.Logger().Info("Retrieved PR force pushes")
	}

	waitForChannelToEmpty(commitsChan)
	if err := s.getRepoActivity(ctx, owner, repo, branchDeletion, commitsChan); err != nil {
		//return err
		ctx.Logger().Error(err, "Failed to retrieve all deleted branches")
	} else {
		ctx.Logger().Info("Retrieved deleted branches")
	}

	waitForChannelToEmpty(commitsChan)
	if err := s.getRepoActivity(ctx, owner, repo, forcePush, commitsChan); err != nil {
		//return err
		ctx.Logger().Error(err, "Failed to retrieve all force pushes")
	} else {
		ctx.Logger().Info("Retrieved force pushes")
	}

	return nil
}

// region Parse repository activity
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

// getRepoActivity
// https://github.com/trufflesecurity/trufflehog/activity
func (s *Source) getRepoActivity(ctx context.Context, owner string, name string, activityType activityType, commitsChan chan string) error {
	var (
		client  = common.SaneHttpClient()
		repoUrl = fmt.Sprintf("https://github.com/%s/%s/activity", owner, name)
		cursor  string
	)

	for {
		ctx.Logger().V(0).Info("Getting repository activity", "owner", owner, "name", name, "type", activityType, "cursor", cursor)

		res, err := getRepoActivityPage(ctx, client, repoUrl, activityType, cursor)
		if err != nil {
			if errors.Is(err, rateLimitError) {
				continue
			}
			return err
		}

		activity := res.Payload.ActivityList
		for _, item := range activity.Items {
			sha := item.Before
			if sha == "" {
				continue
			}

			if danglingCommitsCache.Exists(sha[:8]) {
				ctx.Logger().Info("Skipping commit, it was already found", "commit", sha[:7])
				continue
			}
			danglingCommitsCache.Set(sha[:8], struct{}{})

			select {
			case <-ctx.Done():
				return ctx.Err()
			case commitsChan <- sha:
			default:
				// TODO: Make delay proportional to how full the channel is?
				delay := getRandomDelay(1*time.Second, 30*time.Second)
				ctx.Logger().Info("channel is full. Sleeping.", "delay", delay.String())
				time.Sleep(delay)
				continue
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

//region Pull request activity

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
		ctx.Logger().V(0).Info("Getting pull request force-pushes", "owner", owner, "name", name, "cursor", variables["pullRequestCursor"])

		err := s.graphqlClient.Query(ctx, &q, variables)
		if err != nil {
			if s.handleRateLimit(err) {
				continue
			}
			return err
		}

		for _, n1 := range q.Repository.PullRequests.Nodes {
			for _, n2 := range n1.TimeLineItems.Nodes {
				sha := n2.BeforeCommit.Oid
				if sha == "" {
					continue
				}

				if danglingCommitsCache.Exists(sha[:8]) {
					ctx.Logger().Info("Skipping PR commit, it was already found", "commit", sha[:7])
					continue
				}
				danglingCommitsCache.Set(sha[:8], struct{}{})

				select {
				case <-ctx.Done():
					return ctx.Err()
				case commitsChan <- sha:
				default:
					delay := getRandomDelay(1*time.Second, 30*time.Second)
					ctx.Logger().Info("channel is full. Sleeping.", "delay", delay.String())
					time.Sleep(delay)
					continue
				}
			}

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
