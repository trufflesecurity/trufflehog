package pinecone

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Pinecone API keys follow the pattern: pcsk_{key_id}_{secret}
	// where key_id is 5-6 alphanumeric chars and secret is ~63 alphanumeric chars.
	keyPat = regexp.MustCompile(`\b(pcsk_[A-Za-z0-9]{4,}_[A-Za-z0-9]{40,})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"pcsk_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Pinecone,
			Redacted:     token[:8] + "..." + token[len(token)-4:],
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

		// The key ID is embedded in the token structure (pcsk_{key_id}_{secret}).
		// Extract it unconditionally since it helps identify which key to revoke.
		if keyID := extractKeyID(token); keyID != "" {
			if s1.ExtraData == nil {
				s1.ExtraData = make(map[string]string)
			}
			s1.ExtraData["key_id"] = keyID
		}

		results = append(results, s1)
	}

	return
}

// verifyToken calls the Pinecone List Indexes endpoint (GET /indexes).
// This is a non-state-changing read-only call that validates the API key
// and returns index metadata for the project associated with the key.
// Verification relies on response body structure, not just status codes.
func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.pinecone.io/indexes", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Api-Key", token)
	req.Header.Set("X-Pinecone-Api-Version", "2025-10")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return false, nil, err
	}

	switch res.StatusCode {
	case 200:
		var resData listIndexesResponse
		if err = json.Unmarshal(bodyBytes, &resData); err != nil {
			return false, nil, fmt.Errorf("failed to decode 200 response: %w", err)
		}
		// Body must contain the "indexes" key (even if empty array) to confirm
		// this is a genuine Pinecone response and not a generic 200.
		if !hasIndexesKey(bodyBytes) {
			return false, nil, fmt.Errorf("unexpected response body structure")
		}

		extraData := map[string]string{
			"total_indexes": strconv.Itoa(len(resData.Indexes)),
		}

		// Extract the project ID from the host field. Pinecone hosts follow the
		// pattern: {index-name}-{project_id}.svc.{env}.pinecone.io
		// The project ID is shared across all indexes, so we only need one.
		var projectID string
		for _, idx := range resData.Indexes {
			if pid := extractProjectID(idx.Host); pid != "" {
				projectID = pid
				break
			}
		}
		if projectID != "" {
			extraData["project_id"] = projectID
		}

		for i, idx := range resData.Indexes {
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
		return true, extraData, nil
	case 401:
		// 401 means the key itself is invalid.
		// Pinecone returns plain text "Invalid API Key" or a JSON error body.
		var errResp errorResponse
		if err = json.Unmarshal(bodyBytes, &errResp); err == nil {
			if errResp.Error.Code == "UNAUTHENTICATED" {
				return false, nil, nil
			}
		}
		return false, nil, nil
	case 403:
		// 403 means the key IS valid but lacks control plane permissions
		// (e.g. a DataPlaneViewer/DataPlaneEditor key without ControlPlane roles).
		// This is still a verified credential — it just can't list indexes.
		var errResp errorResponse
		if err = json.Unmarshal(bodyBytes, &errResp); err != nil {
			return false, nil, fmt.Errorf("unexpected 403 response body")
		}
		if errResp.Error.Code == "FORBIDDEN" || errResp.Error.Code == "PERMISSION_DENIED" {
			extraData := map[string]string{
				"permission": "restricted",
			}
			return true, extraData, nil
		}
		return false, nil, fmt.Errorf("unexpected error code in 403 response: %s", errResp.Error.Code)
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// hasIndexesKey checks that the JSON body contains an "indexes" top-level key.
func hasIndexesKey(body []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	_, ok := raw["indexes"]
	return ok
}

// extractKeyID pulls the key identifier from a Pinecone API key.
// Keys follow the format pcsk_{key_id}_{secret}, where key_id is a short
// identifier (5-6 chars) that maps to the key entry in the Pinecone console.
func extractKeyID(token string) string {
	// Strip "pcsk_" prefix, then take everything before the next "_".
	after := strings.TrimPrefix(token, "pcsk_")
	idx := strings.Index(after, "_")
	if idx <= 0 {
		return ""
	}
	return after[:idx]
}

// extractProjectID pulls the project slug from a Pinecone host string.
// Hosts look like: "my-index-abc1234.svc.us-east1-aws.pinecone.io"
// The project ID is the segment between the last hyphen before ".svc" and ".svc".
func extractProjectID(host string) string {
	svcIdx := strings.Index(host, ".svc.")
	if svcIdx == -1 {
		return ""
	}
	prefix := host[:svcIdx]
	lastDash := strings.LastIndex(prefix, "-")
	if lastDash == -1 {
		return ""
	}
	return prefix[lastDash+1:]
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Pinecone
}

func (s Scanner) Description() string {
	return "Pinecone is a vector database service. API keys can be used to manage indexes and perform vector operations."
}

type listIndexesResponse struct {
	Indexes []indexInfo `json:"indexes"`
}

type indexInfo struct {
	Name   string    `json:"name"`
	Host   string    `json:"host"`
	Metric string    `json:"metric"`
	Status indexStatus `json:"status"`
	Spec   indexSpec  `json:"spec"`
}

type indexStatus struct {
	Ready bool   `json:"ready"`
	State string `json:"state"`
}

type indexSpec struct {
	Serverless *serverlessSpec `json:"serverless,omitempty"`
}

type serverlessSpec struct {
	Cloud  string `json:"cloud"`
	Region string `json:"region"`
}

type errorResponse struct {
	Status int `json:"status"`
	Error  struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
