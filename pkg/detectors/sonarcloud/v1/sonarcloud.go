package sonarcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 1 }

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sonar"}) + `(?:^|[^@])\b([0-9a-z]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sonar"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// FromData will find and optionally verify SonarCloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokenMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatchIndex(dataStr, -1) {
		// match[0]:match[1] is the full match (including the optional
		// non-"@" prefix byte captured by the leading non-capturing group),
		// match[2]:match[3] is the 40-char token group.
		fullStart, groupStart, groupEnd := match[0], match[2], match[3]

		// Reject git commit URLs (e.g. github.com/.../commit/<sha>) and
		// "commit/<sha>" paths anywhere in the document. These SHA-1 hashes
		// are 40 lowercase hex chars and otherwise look exactly like a
		// SonarCloud token. See issue #5000.
		windowStart := fullStart
		if windowStart < 0 {
			windowStart = 0
		}
		if endsWithCommitPath(dataStr[windowStart:groupEnd]) {
			continue
		}

		uniqueTokenMatches[dataStr[groupStart:groupEnd]] = struct{}{}
	}

	for match := range uniqueTokenMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_SonarCloud,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			isVerified, verificationErr := s.verifyMatch(ctx, s.getClient(), match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyMatch attempts to validate a SonarCloud token.
func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	url := "https://sonarcloud.io/api/authentication/validate"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(token, "")
	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to perform request: %w", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// The SonarCloud API always returns 200 OK, even for invalid tokens,
	// with the validity indicated in the JSON body.
	if res.StatusCode != http.StatusOK {
		// Treat any non-200 status as a failed attempt to verify.
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	var resp struct {
		Valid bool `json:"valid"`
	}

	if err := json.Unmarshal(bodyBytes, &resp); err != nil {
		return false, fmt.Errorf("invalid JSON: %w", err)
	}

	return resp.Valid, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SonarCloud
}

// endsWithCommitPath reports whether the end of s matches a git commit URL
// path of the form "...commit/<sha>" (optionally URL-encoded with %2F). This
// filters SHA-1 commit hashes reported as SonarCloud false positives; see
// issue #5000.
func endsWithCommitPath(s string) bool {
	idx := strings.LastIndex(strings.ToLower(s), "commit/")
	if idx < 0 {
		return false
	}
	tail := s[idx+len("commit/"):]
	if strings.HasSuffix(tail, "/") {
		return false
	}
	// The remainder must be exactly the 40-char hash that the caller passed in
	// (s already ends at the end of the matched token).
	return len(tail) == 40
}

func (s Scanner) Description() string {
	return "SonarCloud is a cloud-based code quality and security service. SonarCloud tokens can be used to access project analysis and quality reports."
}
