package access_keys

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type scanner struct {
	verificationClient config.HTTPClient
	skipIDs            map[string]struct{}
	detectors.AccountFilter
	detectors.DefaultMultiPartCredentialProvider
}

func New(opts ...func(*scanner)) *scanner {
	scanner := &scanner{
		skipIDs: map[string]struct{}{},
	}
	for _, opt := range opts {
		opt(scanner)
	}

	return scanner
}

func WithSkipIDs(skipIDs []string) func(*scanner) {
	return func(s *scanner) {
		ids := map[string]struct{}{}
		for _, id := range skipIDs {
			ids[id] = struct{}{}
		}

		s.skipIDs = ids
	}
}

func WithAllowedAccounts(accounts []string) func(*scanner) {
	return func(s *scanner) {
		s.SetAllowedAccounts(accounts)
	}
}

func WithDeniedAccounts(accounts []string) func(*scanner) {
	return func(s *scanner) {
		s.SetDeniedAccounts(accounts)
	}
}

// Ensure the scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.CustomResultsCleaner
	detectors.MultiPartCredentialProvider
} = (*scanner)(nil)

var (

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// Key types are from this list https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
	idPat = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s scanner) Keywords() []string {
	return []string{
		"AKIA",
		"ABIA",
		"ACCA",
	}
}

// The recommended way by AWS is to use the SDK's http client.
// https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-http.html
// Note: Using default http.Client causes SignatureInvalid error in response. therefore, based on http default client implementation, we are using the same configuration.
func getDefaultBuildableClient() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().
		WithTimeout(common.DefaultResponseTimeout).
		WithDialerOptions(func(dialer *net.Dialer) {
			dialer.Timeout = 2 * time.Second
			dialer.KeepAlive = 5 * time.Second
		}).
		WithTransportOptions(func(tr *http.Transport) {
			tr.Proxy = http.ProxyFromEnvironment
			tr.MaxIdleConns = 5
			tr.IdleConnTimeout = 5 * time.Second
			tr.TLSHandshakeTimeout = 3 * time.Second
			tr.ExpectContinueTimeout = 1 * time.Second
		})
}

func (s scanner) getAWSBuilableClient() config.HTTPClient {
	if s.verificationClient == nil {
		s.verificationClient = getDefaultBuildableClient()
	}
	return s.verificationClient
}

// FromData will find and optionally verify AWS secrets in a given set of bytes.
func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("aws")
	dataStr := string(data)
	dataStr = aws.UrlEncodedReplacer.Replace(dataStr)

	// Filter & deduplicate matches.
	idMatches := make(map[string]struct{})
	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[matches[1]] = struct{}{}
	}
	secretMatches := make(map[string]struct{})
	for _, matches := range aws.SecretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[matches[1]] = struct{}{}
	}

	// Process matches.
	for idMatch := range idMatches {
		if detectors.StringShannonEntropy(idMatch) < aws.RequiredIdEntropy {
			continue
		}
		if s.skipIDs != nil {
			if _, ok := s.skipIDs[idMatch]; ok {
				continue
			}
		}

		for secretMatch := range secretMatches {
			if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AWS,
				Raw:          []byte(idMatch),
				Redacted:     idMatch,
				RawV2:        []byte(idMatch + ":" + secretMatch),
				ExtraData: map[string]string{
					"resource_type": aws.ResourceTypes[idMatch[:4]],
				},
			}

			// Decode the AWS Account ID.
			accountID, err := aws.GetAccountNumFromID(idMatch)
			isCanary := false
			if err != nil {
				logger.V(3).Info("Failed to decode AWS Account ID", "err", err)
			} else {
				s1.ExtraData["account"] = accountID

				// Check if this is a canary token
				if _, ok := thinkstCanaryList[accountID]; ok {
					isCanary = true
					s1.ExtraData["message"] = thinkstMessage
				}
				if _, ok := thinkstKnockoffsCanaryList[accountID]; ok {
					isCanary = true
					s1.ExtraData["message"] = thinkstKnockoffsMessage
				}

				if isCanary {
					s1.ExtraData["is_canary"] = "true"
				}
			}

			if verify {
				// Check account filtering before verification for ALL secrets (including canaries)
				if accountID != "" {
					if s.ShouldSkipAccount(accountID) {
						var skipReason string
						if s.IsInDenyList(accountID) {
							skipReason = aws.VerificationErrAccountIDInDenyList
						} else {
							skipReason = aws.VerificationErrAccountIDNotInAllowList
						}
						s1.SetVerificationError(fmt.Errorf("%s", skipReason), secretMatch)
						results = append(results, s1)
						continue
					}
				}

				// Perform verification based on token type
				if isCanary {
					// Canary verification logic
					verified, arn, err := s.verifyCanary(ctx, idMatch, secretMatch)
					s1.Verified = verified
					if arn != "" {
						s1.ExtraData["arn"] = arn
					}
					s1.SetVerificationError(err, secretMatch)
				} else {
					// Normal verification logic
					isVerified, extraData, verificationErr := s.verifyMatch(ctx, idMatch, secretMatch, len(secretMatches) > 1)
					s1.Verified = isVerified

					// Log if the calculated ID does not match the ID value from verification.
					// Should only be edge cases at most.
					if accountID != "" && extraData["account"] != "" && extraData["account"] != s1.ExtraData["account"] {
						logger.V(2).Info("Calculated account ID does not match actual account ID", "calculated", accountID, "actual", extraData["account"])
					}

					// Append the extraData to the existing ExtraData map.
					for k, v := range extraData {
						s1.ExtraData[k] = v
					}
					s1.SetVerificationError(verificationErr, secretMatch)
				}
			}

			if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) {
				// Unverified results that look like hashes are probably not secrets
				continue
			}

			results = append(results, s1)
			// If we've found a verified match with this ID, we don't need to look for any more. So move on to the next ID.
			if s1.Verified {
				delete(secretMatches, secretMatch)
				break
			}
		}
	}
	return results, nil
}

func (s scanner) ShouldCleanResultsIrrespectiveOfConfiguration() bool {
	return true
}

const (
	method   = "GET"
	service  = "sts"
	host     = "sts.amazonaws.com"
	region   = "us-east-1"
	endpoint = "https://sts.amazonaws.com"
)

func (s scanner) verifyMatch(ctx context.Context, resIDMatch, resSecretMatch string, retryOn403 bool) (bool, map[string]string, error) {
	// Prep AWS Creds for STS
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithHTTPClient(s.getAWSBuilableClient()),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(resIDMatch, resSecretMatch, ""),
		),
	)
	if err != nil {
		return false, nil, err
	}
	// Create STS client
	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.APIOptions = append(o.APIOptions, replaceUserAgentMiddleware)
	})

	// Make the GetCallerIdentity API call
	resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// Experimentation has indicated that if you make multiple GetCallerIdentity requests within five seconds that
		// share a key ID but are signed with different secrets the second one will be rejected with a 403 that
		// carries a SignatureDoesNotMatch code in its body. This happens even if the second ID-secret pair is
		// valid. Since this is exactly our access pattern, we need to work around it.
		//
		// Fortunately, experimentation has also revealed a workaround: simply resubmit the second request. The
		// response to the resubmission will be as expected.
		//
		// We are clearly deep in the guts of AWS implementation details here, so this all might change with no
		// notice. If you're here because something in this detector broke, you have my condolences.
		if strings.Contains(err.Error(), "StatusCode: 403") {
			if retryOn403 {
				return s.verifyMatch(ctx, resIDMatch, resSecretMatch, false)
			}
			return false, nil, nil
		} else if strings.Contains(err.Error(), "InvalidClientTokenId") {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("request returned unexpected error: %w", err)
	}

	extraData := map[string]string{
		"rotation_guide": "https://howtorotate.com/docs/tutorials/aws/",
		"account":        *resp.Account,
		"user_id":        *resp.UserId,
		"arn":            *resp.Arn,
	}
	return true, extraData, nil
}

func (s scanner) CleanResults(results []detectors.Result) []detectors.Result {
	return aws.CleanResults(results)
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AWS
}

func (s scanner) Description() string {
	return "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached."
}

// Adds a custom Build middleware to the stack to replace the User-Agent header of the final request
// https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/middleware.html
func replaceUserAgentMiddleware(stack *middleware.Stack) error {
	return stack.Build.Add(
		middleware.BuildMiddlewareFunc(
			"ReplaceUserAgent",
			func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (
				out middleware.BuildOutput, metadata middleware.Metadata, err error,
			) {
				req, ok := in.Request.(*smithyhttp.Request)
				if !ok {
					return next.HandleBuild(ctx, in)
				}
				req.Header.Set("User-Agent", common.UserAgent())
				return next.HandleBuild(ctx, in)
			},
		),
		middleware.After,
	)
}
