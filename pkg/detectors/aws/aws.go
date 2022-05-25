package aws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// Key types are from this list https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
	keyPat = regexp.MustCompile(`\b([A-Za-z0-9+/]{40})\b`)
	idPat  = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{
		"AKIA",
		"ABIA",
		"ACCA",
		"ASIA",
	}
}

func GetHash(input string) string {
	data := []byte(input)
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

func GetHMAC(key []byte, data []byte) []byte {
	hasher := hmac.New(sha256.New, key)
	hasher.Write(data)
	return hasher.Sum(nil)
}

// FromData will find and optionally verify AWS secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AWS,
				Raw:          []byte(resMatch),
			}

			if verify {
				// REQUEST VALUES.
				method := "GET"
				service := "sts"
				host := "sts.amazonaws.com"
				region := "us-east-1"
				endpoint := "https://sts.amazonaws.com"
				datestamp := time.Now().UTC().Format("20060102")
				amzDate := time.Now().UTC().Format("20060102T150405Z0700")

				req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
				if err != nil {
					continue
				}

				// TASK 1: CREATE A CANONICAL REQUEST.
				// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
				canonicalURI := "/"
				canonicalHeaders := "host:" + host + "\n"
				signedHeaders := "host"
				algorithm := "AWS4-HMAC-SHA256"
				credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)

				params := req.URL.Query()
				params.Add("Action", "GetCallerIdentity")
				params.Add("Version", "2011-06-15")
				params.Add("X-Amz-Algorithm", algorithm)
				params.Add("X-Amz-Credential", resIdMatch+"/"+credentialScope)
				params.Add("X-Amz-Date", amzDate)
				params.Add("X-Amz-Expires", "30")
				params.Add("X-Amz-SignedHeaders", signedHeaders)

				canonicalQuerystring := params.Encode()
				payloadHash := GetHash("") //empty payload
				canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQuerystring + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash

				// TASK 2: CREATE THE STRING TO SIGN.
				stringToSign := algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" + GetHash(canonicalRequest)

				// TASK 3: CALCULATE THE SIGNATURE.
				// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
				hash := GetHMAC([]byte(fmt.Sprintf("AWS4%s", resMatch)), []byte(datestamp))
				hash = GetHMAC(hash, []byte(region))
				hash = GetHMAC(hash, []byte(service))
				hash = GetHMAC(hash, []byte("aws4_request"))

				signature2 := GetHMAC(hash, []byte(stringToSign)) //Get Signature HMAC SHA256
				signature := hex.EncodeToString(signature2)

				// TASK 4: ADD SIGNING INFORMATION TO THE REQUEST.
				params.Add("X-Amz-Signature", signature)
				req.Header.Add("Content-type", "application/x-www-form-urlencoded; charset=utf-8")
				req.URL.RawQuery = params.Encode()

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears "random" enough to be a real key.
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)
		}
	}
	return detectors.CleanResults(results), nil
}
