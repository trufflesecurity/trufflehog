package gcshmac

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client   *http.Client
	endpoint string
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

const (
	defaultEndpoint = "https://storage.googleapis.com/"

	// GCS accepts SigV4 with either "auto" or "us-east-1" as the region.
	signingRegion  = "auto"
	signingService = "s3"

	// SHA-256 of an empty body.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	serviceAccountIDLen = 61
)

var (
	defaultClient = common.SaneHttpClient()

	// Access IDs are 61 characters for service accounts and 24 for user accounts.
	// https://cloud.google.com/storage/docs/authentication/hmackeys
	idPat = regexp.MustCompile(`\b(GOOG[A-Z0-9]{20}(?:[A-Z0-9]{37})?)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"GOOG"}
}

// FromData will find and optionally verify Cloud Storage HMAC keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := aws.UrlEncodedReplacer.Replace(string(data))

	idMatches := make(map[string]struct{})
	for _, m := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[m[1]] = struct{}{}
	}
	if len(idMatches) == 0 {
		return nil, nil
	}

	secretMatches := make(map[string]struct{})
	for _, m := range aws.SecretPat.FindAllStringSubmatch(dataStr, -1) {
		if detectors.StringShannonEntropy(m[1]) < aws.RequiredSecretEntropy {
			continue
		}
		secretMatches[m[1]] = struct{}{}
	}

	var results []detectors.Result
	for id := range idMatches {
		if detectors.StringShannonEntropy(id) < aws.RequiredIdEntropy {
			continue
		}

		for secret := range secretMatches {
			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_GCSHMACKey,
				Raw:          []byte(id),
				RawV2:        []byte(id + ":" + secret),
				Redacted:     id,
				SecretParts: map[string]string{
					"access_id": id,
					"secret":    secret,
				},
				ExtraData: map[string]string{
					"account_type": accountType(id),
				},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				endpoint := s.endpoint
				if endpoint == "" {
					endpoint = defaultEndpoint
				}
				verified, verr := verifyHMACKey(ctx, client, endpoint, id, secret)
				r.Verified = verified
				r.SetVerificationError(verr, secret)
			}

			if !r.Verified && aws.FalsePositiveSecretPat.MatchString(secret) {
				continue
			}

			results = append(results, r)
			if r.Verified {
				delete(secretMatches, secret)
				break
			}
		}
	}

	return results, nil
}

func accountType(id string) string {
	if len(id) == serviceAccountIDLen {
		return "service_account"
	}
	return "user_account"
}

type xmlError struct {
	Code string `xml:"Code"`
}

// verifyHMACKey signs a ListBuckets call against the XML API. A key that signs
// correctly but lacks storage.buckets.list still authenticated, so AccessDenied
// counts as verified.
func verifyHMACKey(ctx context.Context, client *http.Client, endpoint, id, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-amz-content-sha256", emptyPayloadHash)

	creds := awssdk.Credentials{AccessKeyID: id, SecretAccessKey: secret}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, emptyPayloadHash, signingService, signingRegion, time.Now()); err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, res.Body)
		return true, nil
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	if err != nil {
		return false, err
	}
	var e xmlError
	_ = xml.Unmarshal(body, &e)

	switch e.Code {
	case "AccessDenied":
		return true, nil
	case "InvalidAccessKeyId", "SignatureDoesNotMatch", "InvalidSecurity":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d, code %q", res.StatusCode, e.Code)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GCSHMACKey
}

func (s Scanner) Description() string {
	return "Cloud Storage HMAC keys are an access ID and secret pair used to sign requests to Google Cloud Storage's S3-compatible XML API."
}
