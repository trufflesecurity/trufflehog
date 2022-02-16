package alibaba

import (
	"context"
	"regexp"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	log "github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat    = regexp.MustCompile(`\b(LTAI[a-zA-Z0-9]{17,21})[\"' ;\s]*`)
	secretPat = regexp.MustCompile(`\b([a-zA-Z0-9]{30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"LTAI"}
}

// FromData will find and optionally verify Alibaba secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		//Plausible key pat found, look for secrets match
		secMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

		for _, secMatch := range secMatches {

			if len(match) != 2 {
				continue
			}

			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_Alibaba,
				Raw:          []byte(match[1]),
				Redacted:     match[1],
			}

			if verify {
				ecsClient, err := ecs.NewClientWithAccessKey(
					"us-east-1", // your region ID
					match[1],    // your AccessKey ID
					secMatch[1]) // your AccessKey Secret
				if err != nil {
					log.WithError(err).Debug("error creating alibaba client, skipping")
					continue
				}
				// Create an API request and set parameters
				request := ecs.CreateDescribeInstancesRequest()
				request.ConnectTimeout = time.Duration(5) * time.Second
				request.Scheme = "https"
				request.Domain = "ecs.aliyuncs.com"
				// Initiate the request and handle exceptions
				_, err = ecsClient.DescribeInstances(request)
				if err != nil {
					s.Verified = false

				} else {
					s.Verified = true
				}
			}

			if !s.Verified {
				if detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
					continue
				}
			}

			results = append(results, s)
		}
	}
	return
}
