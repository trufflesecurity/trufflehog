package trufflehogenterprisescanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"trufflehogenterprisescanner"}) + `\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"trufflehogenterprisescanner"}
}

// FromData will find and optionally verify Trufflehogenterprisescanner secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_TrufflehogEnterpriseScanner,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.trufflehogenterprisescanner.com/apps", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.trufflehogenterprisescanner+json; version=3")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TrufflehogEnterpriseScanner
}

func grpcHeartbeat(group, token string) error {
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx,
		metadata.New(map[string]string{
			"name":          strings.TrimSpace(group),
			"authorization": strings.TrimSpace(token),
		}))

	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		panic(errors.Wrap(err, "cannot load root CA certs"))
	}
	creds := credentials.NewTLS(&tls.Config{
		RootCAs: systemRoots,
	})

	conn, err := grpc.Dial("real-strong-chipmunk.api.c1.prod.trufflehog.org:8443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	c := pb.NewAgentServiceClient(conn)

	r, err := c.Heartbeat(ctx, &pb.HeartbeatRequest{Status: "GOOD", Reason: "", Version: "v1.0.0"})
	if err != nil {
		log.Fatalf("could not heartbeat: %v", err)
	}
	log.Printf("Heartbeat response: %s", r)
}
