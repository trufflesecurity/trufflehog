package mongodb

import (
	"context"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(mongodb(\+srv)?://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+)\b`)
	// TODO: Add support for sharded cluster, replica set and Atlas Deployment.
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mongodb"}
}

// FromData will find and optionally verify MongoDB secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MongoDB,
			Raw:          []byte(resMatch),
		}

		if verify {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				client, err := mongo.Connect(ctx, options.Client().ApplyURI(resMatch))
				if err != nil {
					return
				}
				defer func() {
					if err := client.Disconnect(ctx); err != nil {
						return
					}
				}()
				if err := client.Ping(ctx, readpref.Primary()); err != nil {
					return
				}
				s1.Verified = true
			}()
		}
		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MongoDB
}
