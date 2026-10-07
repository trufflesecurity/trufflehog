package pinecone

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"

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

	// Pinecone API keys follow the pattern: pcsk_{label}_{secret}
	// where label is 5-6 alphanumeric chars and secret is exactly 63 alphanumeric
	// chars (total length 74-75). Tight bounds prevent over-reading into adjacent
	// text and rule out partial/malformed matches.
	// Group 1 = whole token, group 2 = label (surfaced as ExtraData["key_id"]).
	keyPat = regexp.MustCompile(`\b(pcsk_([A-Za-z0-9]{5,6})_[A-Za-z0-9]{63})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"pcsk_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Pinecone secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]string)
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = match[2]
	}

	for token, keyID := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
			Redacted:     token[:8] + "..." + token[len(token)-4:],
			ExtraData:    map[string]string{"key_id": keyID},
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			isVerified, extraData, verificationErr := s.verifyMatch(ctx, s.getClient(), token)
			s1.Verified = isVerified
			maps.Copy(s1.ExtraData, extraData)
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyMatch calls the Pinecone List Indexes endpoint (GET /indexes) to validate the key.
// Per the Pinecone API reference, this control-plane endpoint returns 200/401/500.
// 403 is not documented but is observed in practice for valid keys that lack
// ControlPlane permissions (e.g. DataPlaneViewer role).
func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pinecone.io/indexes", http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Api-Key", token)
	req.Header.Set("X-Pinecone-Api-Version", "2025-10")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return false, nil, err
		}
		var apiResp listIndexesResponse
		if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
			return false, nil, fmt.Errorf("failed to decode 200 response: %w", err)
		}
		// Guard against a generic 200 that doesn't have the "indexes" key at all:
		// JSON unmarshal leaves Indexes as nil in that case, which we treat as a
		// malformed response rather than a legitimate empty-indexes result.
		if apiResp.Indexes == nil {
			return false, nil, fmt.Errorf("unexpected response body structure")
		}
		return true, buildIndexExtraData(apiResp.Indexes), nil

	case http.StatusUnauthorized:
		return false, nil, nil

	case http.StatusForbidden:
		// 403 means the key authenticated but lacks permission for this endpoint.
		// Official docs do not mention this, but the apikey creation allows setting custom permissions,
		// and we have observed 403 responses in practice for valid keys with insufficient permissions.
		// We treat this as "verified but with limited permissions" rather than indeterminate
		return true, map[string]string{"permission": "restricted"}, nil

	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

// extractProjectID pulls the project slug from a Pinecone index host string.
// Hosts follow the pattern: {index-name}-{project_id}.svc.{env}.pinecone.io
func extractProjectID(host string) string {
	prefix, _, ok := strings.Cut(host, ".svc.")
	if !ok {
		return ""
	}
	lastDash := strings.LastIndex(prefix, "-")
	if lastDash == -1 {
		return ""
	}
	return prefix[lastDash+1:]
}

// buildIndexExtraData derives human-useful context (project id, up to 5 index
// summaries) from the list-indexes response. Returns nil when there are no
// indexes to describe.
func buildIndexExtraData(indexes []indexInfo) map[string]string {
	extraData := map[string]string{
		"total_indexes": strconv.Itoa(len(indexes)),
	}

	for _, idx := range indexes {
		if pid := extractProjectID(idx.Host); pid != "" {
			extraData["project_id"] = pid
			break
		}
	}

	for i, idx := range indexes {
		if i >= 5 {
			break
		}
		prefix := fmt.Sprintf("index_%d_", i)
		extraData[prefix+"name"] = idx.Name
		extraData[prefix+"host"] = idx.Host
		if idx.Spec.Serverless != nil {
			extraData[prefix+"cloud"] = idx.Spec.Serverless.Cloud
			extraData[prefix+"region"] = idx.Spec.Serverless.Region
		}
	}

	return extraData
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Pinecone
}

func (s Scanner) Description() string {
	return "Pinecone is a vector database service. API keys can be used to manage indexes and perform vector operations."
}
