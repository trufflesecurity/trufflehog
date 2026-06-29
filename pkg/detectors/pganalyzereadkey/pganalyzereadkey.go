package pganalyzereadkey

import (
	"context"
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

// Compile-time interface check
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// pganalyze Read API keys use the format:
	// pgar_<27 alphanumeric characters>
	//
	// Example:
	// pgar_abcdefghijklmnopqrstuvwxyz12
	pganalyzeTokenPat = regexp.MustCompile(
		`\b(pgar_[A-Za-z0-9]{27})\b`,
	)
)

// Keywords used for fast pre-filtering
func (s Scanner) Keywords() []string {
	return []string{
		"pgar_",
	}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData scans for pganalyze API tokens and optionally verifies them.
func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})

	matches := pganalyzeTokenPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_PgAnalyzeReadKey,
			Raw:          []byte(token),
			SecretParts: map[string]string{
				"key":         token,
				"access_type": "read",
			},
		}

		if verify {
			verified, verificationErr := verifyPganalyzeToken(
				ctx,
				s.getClient(),
				token,
			)

			result.SetVerificationError(verificationErr, token)
			result.Verified = verified
		}

		results = append(results, result)
	}

	return
}

func verifyPganalyzeToken(
	ctx context.Context,
	client *http.Client,
	token string,
) (bool, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://app.pganalyze.com/graphql",
		http.NoBody,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Token "+token)

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

	// Explicit invalid auth
	case http.StatusUnauthorized:
		return false, nil

	default:
		return false, fmt.Errorf(
			"unexpected HTTP response status %d",
			res.StatusCode,
		)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_PgAnalyzeReadKey
}

func (s Scanner) Description() string {
	return "pganalyze is a PostgreSQL monitoring and performance analysis platform. pganalyze Read API keys can be used to access read-only monitoring and query performance data."
}
