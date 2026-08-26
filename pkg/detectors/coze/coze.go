package coze

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Coze personal access tokens look like: pat_ + 64 alphanumeric characters.
	keyPat = regexp.MustCompile(`\b(pat_[A-Za-z0-9]{64})\b`)

	// Tokens may belong to either the international or China API surface.
	apiBases = []string{
		"https://api.coze.com",
		"https://api.coze.cn",
	}
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"pat_"}
}

// FromData will find and optionally verify Coze personal access tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Coze,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

type cozeAPIResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	var lastErr error

	for _, base := range apiBases {
		verified, err := verifyAgainstBase(ctx, client, base, token)
		if verified {
			return true, nil
		}
		if err != nil {
			lastErr = err
			continue
		}
		// Determinate auth failure on this host — try the other region before giving up.
	}

	return false, lastErr
}

func verifyAgainstBase(ctx context.Context, client *http.Client, base, token string) (bool, error) {
	// List workspaces is a lightweight, non-destructive call that authenticates the PAT.
	// Docs: https://www.coze.com/docs/developer_guides/list_workspace
	url := base + "/v1/workspaces?page_num=1&page_size=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil {
		return false, err
	}

	var apiRes cozeAPIResponse
	_ = json.Unmarshal(body, &apiRes)

	switch res.StatusCode {
	case http.StatusOK:
		// Determinate success: key is live and can list workspaces.
		return true, nil
	case http.StatusForbidden:
		// Code 4101 means the token authenticated but lacks the listWorkspace permission.
		// That is still a live credential.
		if apiRes.Code == 4101 {
			return true, nil
		}
		return false, fmt.Errorf("unexpected HTTP response status %d from %s", res.StatusCode, base)
	case http.StatusUnauthorized:
		// Determinate failure: key is invalid for this host. No error object.
		return false, nil
	default:
		// Indeterminate: unexpected status (rate limit, 5xx, etc).
		return false, fmt.Errorf("unexpected HTTP response status %d from %s", res.StatusCode, base)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Coze
}

func (s Scanner) Description() string {
	return "Coze is an AI agent platform. Personal access tokens (PATs) can be used to authenticate to the Coze OpenAPI and manage bots, workspaces, and related resources."
}
