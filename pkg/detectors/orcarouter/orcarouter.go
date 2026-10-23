// Package orcarouter detects and verifies OrcaRouter API keys.
package orcarouter

import (
	"context"
	"encoding/json"
	"errors"
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

const (
	// DefaultAPIBase is the public OrcaRouter OpenAI-compatible API origin.
	// OrcaRouter keys are issued by the www.orcarouter.ai auth origin but are
	// only ever used against this API origin.
	DefaultAPIBase = "https://api.orcarouter.ai/v1"

	modelsPath = "/models"
	keyPrefix  = "sk-orca-"
)

// Scanner detects OrcaRouter API keys.
type Scanner struct {
	client *http.Client
	// apiBase overrides DefaultAPIBase in tests. It is empty in production.
	apiBase string
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// OrcaRouter API keys are prefixed with sk-orca- and carry a URL-safe
	// random suffix. The bounds keep obvious placeholders out while accepting
	// every issued key shape.
	keyPat = regexp.MustCompile(`\b(sk-orca-[A-Za-z0-9_-]{16,128})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{keyPrefix}
}

// FromData will find and optionally verify OrcaRouter secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		result := detectors.Result{
			DetectorType: s.Type(),
			Redacted:     redact(token),
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			verified, extraData, verificationErr := s.verifyToken(ctx, token)
			result.Verified = verified
			result.ExtraData = extraData
			result.SetVerificationError(verificationErr)
		}

		results = append(results, result)
	}

	return results, err
}

func (s Scanner) httpClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) endpoint() string {
	if s.apiBase != "" {
		return strings.TrimSuffix(s.apiBase, "/")
	}
	return DefaultAPIBase
}

// verifyToken calls GET /v1/models with the candidate key. That is the same
// catalog endpoint the provider uses for model discovery, so a successful
// verification also proves the key can actually serve inference.
func (s Scanner) verifyToken(ctx context.Context, token string) (bool, map[string]string, error) {
	catalog, status, err := s.fetchCatalog(ctx, token)
	if err != nil {
		return false, nil, err
	}

	switch status {
	case http.StatusOK:
		return true, catalogCounts(catalog), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The key is well formed but not valid (revoked, disabled or unknown).
		return false, nil, nil
	case http.StatusTooManyRequests:
		return false, nil, errors.New("orcarouter verification rate limited")
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", status)
	}
}

func (s Scanner) fetchCatalog(ctx context.Context, token string) (Catalog, int, error) {
	var catalog Catalog

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint()+modelsPath, nil)
	if err != nil {
		return catalog, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := s.httpClient().Do(req)
	if err != nil {
		return catalog, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return catalog, res.StatusCode, nil
	}

	// A catalog payload is a few hundred kilobytes at most; bound the read so a
	// misbehaving endpoint cannot exhaust memory.
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&catalog); err != nil {
		return Catalog{}, res.StatusCode, fmt.Errorf("decoding orcarouter model catalog: %w", err)
	}
	return catalog, res.StatusCode, nil
}

// catalogCounts renders the capability summary as detector extra data. Only
// counts are reported; nothing derived from the credential is included.
func catalogCounts(catalog Catalog) map[string]string {
	counts := catalog.Counts()
	extraData := make(map[string]string, len(counts))
	for name, count := range counts {
		extraData[name] = strconv.Itoa(count)
	}
	return extraData
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_OrcaRouter
}

func (s Scanner) Version() int {
	return 1
}

func (s Scanner) Description() string {
	return "OrcaRouter is an OpenAI-compatible AI gateway that routes many model providers behind one endpoint."
}

// redact keeps a recognisable prefix and the last four characters so operators
// can identify a finding without exposing the credential.
func redact(token string) string {
	const visible = 4
	if len(token) <= visible*2 {
		return "..." + token
	}
	return token[:len(keyPrefix)+visible] + "..." + token[len(token)-visible:]
}
