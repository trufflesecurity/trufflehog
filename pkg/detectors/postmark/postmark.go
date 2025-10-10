package postmark

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"postmark"}) + `\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"postmark"}
}

// FromData will find and optionally verify Postmark secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Postmark,
			Raw:          []byte(resMatch),
		}

		if verify {
			valid, extraData, err := verifyKey(ctx, client, resMatch)
			s1.Verified = valid
			s1.ExtraData = extraData
			s1.SetVerificationError(err)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyKey verifies a Postmark key by making requests to the Postmark API.
// It tries both server and account API key verification.
func verifyKey(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	errs := make([]error, 0, 2)

	// Try verifying as server API key first
	valid, err := verifyServerAPIKey(ctx, client, key)
	if valid {
		// If valid as server API key, return immediately
		return true, map[string]string{"type": "server"}, nil
	}
	if err != nil {
		errs = append(errs, err)
	}

	// Try verifying as account API key next
	valid, err = verifyAccountAPIKey(ctx, client, key)
	if valid {
		// If valid as account API key, return immediately
		return true, map[string]string{"type": "account"}, nil
	}
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		// If there were errors during verification, return them
		return false, nil, errors.Join(errs...)
	}
	return false, nil, nil
}

// verifyServerAPIKey verifies a Postmark server API key by making a request to the Postmark API.
func verifyServerAPIKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	return verifyKeyWithOptions(
		ctx,
		client,
		key,
		"/deliverystats",
		"X-Postmark-Server-Token",
	)
}

// verifyAccountAPIKey verifies a Postmark account API key by making a request to the Postmark API.
func verifyAccountAPIKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	return verifyKeyWithOptions(
		ctx,
		client,
		key,
		"/domains?count=10&offset=0",
		"X-Postmark-Account-Token",
	)
}

// verifyKeyWithOptions is a generic function to verify a Postmark key with given endpoint and header.
func verifyKeyWithOptions(ctx context.Context, client *http.Client, key, endpoint, authHeader string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.postmarkapp.com"+endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(authHeader, key)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postmark
}

func (s Scanner) Description() string {
	return "Postmark is an email delivery service. Postmark server tokens can be used to access and manage email delivery and statistics."
}
