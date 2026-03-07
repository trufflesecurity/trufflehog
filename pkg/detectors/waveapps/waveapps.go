package waveapps

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
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// graphQLResponse represents the response from the Waveapps GraphQL API.
type graphQLResponse struct {
	Data struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"data"`
	Errors []interface{} `json:"errors"`
}

type Scanner struct {
	client *http.Client
}

const waveappsURL = "https://gql.waveapps.com/graphql/public"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Wave payment tokens have distinct prefixes: wave_sn_prod_ or wave_ci_prod_
	// These are Waveapps (waveapps.com) API token types, not country codes.
	// Ref: https://developer.waveapps.com/hc/en-us/articles/360018856751-Authentication
	keyPat = regexp.MustCompile(`\b(wave_(?:sn|ci)_prod_[A-Za-z0-9_-]{30,})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"wave_sn_prod_", "wave_ci_prod_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Waveapps secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Waveapps,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyWaveapps(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyWaveapps(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Use a simple user query to verify the token is valid.
	payload := strings.NewReader(`{"query":"{ user { id } }"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, waveappsURL, payload)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	switch res.StatusCode {
	case http.StatusOK:
		var resp graphQLResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return false, err
		}

		// If GraphQL returned errors, the token is invalid.
		if len(resp.Errors) > 0 {
			return false, nil
		}

		// A valid token returns a non-empty user ID.
		if resp.Data.User.ID != "" {
			return true, nil
		}
		return false, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Waveapps
}

func (s Scanner) Description() string {
	return "Waveapps is a financial software platform for small businesses. Waveapps API tokens can be used to access payment and invoicing data via their GraphQL API."
}
