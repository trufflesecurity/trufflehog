package trufflehogenterprisescanner

import (
	"context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	//"trufflehog/pkg/grpcapi"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat     = regexp.MustCompile(`\bthog-agent-[0-9a-f]{32}\b`)
	groupPat   = regexp.MustCompile(`\bthog-scanner-[a-zA-Z]+\b`)
	addressPat = regexp.MustCompile(`\b[a-z]+-[a-z]+-[a-z]+\.[a-z][0-9]\.[a-z]+\.trufflehog\.org:\d{4}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"thog"}
}

// FromData will find and optionally verify TrufflehogEnterpriseScanner secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	groupMatches := groupPat.FindAllStringSubmatch(dataStr, -1)
	addressMatches := addressPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 1 {
			continue
		}
		resKeyMatch := strings.TrimSpace(keyMatch[1])

		for _, groupMatch := range groupMatches {
			if len(groupMatch) != 1 {
				continue
			}
			resGroupMatch := strings.TrimSpace(groupMatch[1])

			for _, addressMatch := range addressMatches {
				if len(addressMatch) != 1 {
					continue
				}

				resAddressMatch := strings.TrimSpace(addressMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_TrufflehogEnterpriseScanner,
					Raw:          []byte(resKeyMatch),
				}

				if verify {
					err := grpcHeartbeat(resAddressMatch, resGroupMatch, resKeyMatch)
					if err == nil {
						s1.Verified = true
					}
				}
				results = append(results, s1)
			}
		}
	}
	return results, nil

}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TrufflehogEnterpriseScanner
}

func grpcHeartbeat(address, group, token string) error {
	//	ctx := context.Background()
	//	ctx = metadata.NewOutgoingContext(ctx,
	//		metadata.New(map[string]string{
	//			"name":          strings.TrimSpace(group),
	//			"authorization": strings.TrimSpace(token),
	//		}))
	//
	//	systemRoots, err := x509.SystemCertPool()
	//	if err != nil {
	//		panic(errors.Wrap(err, "cannot load root CA certs"))
	//	}
	//	creds := credentials.NewTLS(&tls.Config{
	//		RootCAs: systemRoots,
	//	})
	//
	//	conn, err := grpc.Dial("real-strong-chipmunk.api.c1.prod.trufflehog.org:8443", grpc.WithTransportCredentials(creds))
	//	if err != nil {
	//		log.Fatalf("Did not connect: %v", err)
	//	}
	//	defer conn.Close()
	//
	//	c := grpcapi.NewAgentServiceClient(conn)
	//
	//	r, err := c.Heartbeat(ctx, &pb.HeartbeatRequest{Status: "GOOD", Reason: "", Version: "v1.0.0"})
	//	if err != nil {
	//		log.Fatalf("could not heartbeat: %v", err)
	//	}
	//	log.Printf("Heartbeat response: %s", r)
}
