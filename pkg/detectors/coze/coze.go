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
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pat_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Coze secrets in a given set of bytes.
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
			Redacted:     match[:8] + "...",
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			isVerified, extraData, verificationErr := verifyMatch(ctx, s.getClient(), match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

type cozeAPIResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	var lastErr error

	for _, base := range apiBases {
		verified, extra, err := verifyAgainstBase(ctx, client, base, token)
		if verified {
			return true, extra, nil
		}
		if err != nil {
			lastErr = err
			continue
		}
		// Determinate auth failure on this host — try the other region before giving up.
	}

	return false, nil, lastErr
}

func verifyAgainstBase(ctx context.Context, client *http.Client, base, token string) (bool, map[string]string, error) {
	// List workspaces is a lightweight, non-destructive call that authenticates the PAT.
	// Docs: https://www.coze.com/docs/developer_guides/list_workspace
	url := base + "/v1/workspaces?page_num=1&page_size=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil {
		return false, nil, err
	}

	var apiRes cozeAPIResponse
	_ = json.Unmarshal(body, &apiRes)

	switch res.StatusCode {
	case http.StatusOK:
		return true, map[string]string{"api_base": base}, nil
	case http.StatusForbidden:
		// Code 4101 means the token authenticated but lacks the listWorkspace permission.
		// That is still a live credential.
		if apiRes.Code == 4101 {
			return true, map[string]string{
				"api_base":            base,
				"permission_required": "listWorkspace",
			}, nil
		}
		return false, nil, fmt.Errorf("unexpected HTTP response status %d from %s", res.StatusCode, base)
	case http.StatusUnauthorized:
		// Code 4100: authentication is invalid for this host.
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d from %s", res.StatusCode, base)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Coze
}

func (s Scanner) Description() string {
	return "Coze is an AI agent platform. Personal access tokens (PATs) can be used to authenticate to the Coze OpenAPI and manage bots, workspaces, and related resources."
}
