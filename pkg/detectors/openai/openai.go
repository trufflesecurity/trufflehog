package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// The magic string T3BlbkFJ is the base64-encoded string: OpenAI
	keyPat = regexp.MustCompile(`\b(sk-(?:proj-|svcacct-)?[[:alnum:]_-]+T3BlbkFJ[[:alnum:]_-]+)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"T3BlbkFJ"}
}

// FromData will find and optionally verify OpenAI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OpenAI,
			Redacted:     token[:3] + "..." + token[min(len(token)-1, 47):],
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, extraData, verificationErr := verifyToken(ctx, client, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
			s1.AnalysisInfo = map[string]string{"key": token}
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/me", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case 200:
		var resData response
		if err = json.NewDecoder(res.Body).Decode(&resData); err != nil {
			return false, nil, err
		}

		extraData := map[string]string{
			"id":          resData.ID,
			"total_orgs":  fmt.Sprintf("%d", len(resData.Orgs.Data)),
			"mfa_enabled": strconv.FormatBool(resData.MfaFlagEnabled),
			"created_at":  time.Unix(int64(resData.Created), 0).Format(time.RFC3339),
		}

		if len(resData.Orgs.Data) > 0 {
			extraData["description"] = resData.Orgs.Data[0].Description
			extraData["is_personal"] = strconv.FormatBool(resData.Orgs.Data[0].Personal)
			extraData["is_default"] = strconv.FormatBool(resData.Orgs.Data[0].IsDefault)
		}
		return true, extraData, nil
	case 401:
		// Invalid
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenAI
}

func (s Scanner) Description() string {
	return "OpenAI provides various AI models and services. The API keys can be used to access and interact with these models and services."
}

type response struct {
	Object                   string `json:"object"`
	ID                       string `json:"id"`
	Email                    any    `json:"email"`
	Name                     any    `json:"name"`
	Picture                  any    `json:"picture"`
	Created                  int    `json:"created"`
	PhoneNumber              any    `json:"phone_number"`
	MfaFlagEnabled           bool   `json:"mfa_flag_enabled"`
	Orgs                     orgs   `json:"orgs"`
	HasProjectsArchive       bool   `json:"has_projects_archive"`
	HasPaygProjectSpendLimit bool   `json:"has_payg_project_spend_limit"`
	Amr                      []any  `json:"amr"`
}
type settings struct {
	ThreadsUIVisibility      string `json:"threads_ui_visibility"`
	UsageDashboardVisibility string `json:"usage_dashboard_visibility"`
}
type projects struct {
	Object string `json:"object"`
	Data   []any  `json:"data"`
}
type data struct {
	Object      string   `json:"object"`
	ID          string   `json:"id"`
	Created     int      `json:"created"`
	Title       string   `json:"title"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Personal    bool     `json:"personal"`
	Settings    settings `json:"settings"`
	ParentOrgID any      `json:"parent_org_id"`
	IsDefault   bool     `json:"is_default"`
	Role        string   `json:"role"`
	Projects    projects `json:"projects"`
}
type orgs struct {
	Object string `json:"object"`
	Data   []data `json:"data"`
}
