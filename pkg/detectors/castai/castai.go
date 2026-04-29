package castai

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

func New(opts ...func(*scanner)) *scanner {
	scanner := &scanner{}

	// Default endpoints.
	_ = scanner.SetConfiguredEndpoints(
		"https://api.cast.ai/v1/kubernetes/external-clusters",
		"https://api.eu.cast.ai/v1/kubernetes/external-clusters",
	)

	for _, opt := range opts {
		opt(scanner)
	}

	return scanner
}

func WithClient(c *http.Client) func(*scanner) {
	return func(s *scanner) {
		s.client = c
	}
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*scanner)(nil)
var _ detectors.EndpointCustomizer = (*scanner)(nil)
var _ detectors.Versioner = (*scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(castai_v1_[a-z0-9]{64}_[a-z0-9]{8})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s scanner) Keywords() []string {
	return []string{"castai_v1_"} // Prefix
}

func (scanner) Version() int {
	return 1
}

// FromData will find and optionally verify Castai secrets in a given set of bytes.
func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CastAI,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			for _, endpoint := range s.Endpoints() {
				isVerified, extraData, verificationErr := verifyMatch(ctx, client, endpoint, match)
				// A token can only be valid in a single environment.
				if !isVerified && verificationErr == nil {
					continue
				}

				s1.Verified = isVerified
				s1.ExtraData = map[string]string{
					"endpoint": endpoint,
				}
				maps.Copy(s1.ExtraData, extraData)
				s1.SetVerificationError(verificationErr, match)
				break
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, endpoint string, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("X-API-Key", token)

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CastAI
}

func (s scanner) Description() string {
	return "Castai is a blockchain development platform that provides a suite of tools and services for building and scaling decentralized applications. Castai API keys can be used to access these services."
}
