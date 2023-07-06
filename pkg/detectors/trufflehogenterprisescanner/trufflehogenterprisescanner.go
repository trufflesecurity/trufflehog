package trufflehogenterprisescanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/trufflehogenterprisescanner/scannerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat     = regexp.MustCompile(`\bthog-agent-[0-9a-f]{32}\b`)
	groupPat   = regexp.MustCompile(`\bthog-scanner-[a-zA-Z]+\b`)
	addressPat = regexp.MustCompile(`\b[a-z]+-[a-z]+-[a-z]+.[a-z]+\.[a-z][0-9]\.[a-z]+\.trufflehog\.org:[0-9]{4}\b`)
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
		resKeyMatch := strings.TrimSpace(keyMatch[0])

		for _, groupMatch := range groupMatches {
			if len(groupMatch) != 1 {
				continue
			}
			resGroupMatch := strings.TrimSpace(groupMatch[0])

			for _, addressMatch := range addressMatches {
				if len(addressMatch) != 1 {
					continue
				}

				resAddressMatch := strings.TrimSpace(addressMatch[0])

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

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return errors.Wrap(err, "cannot dial")
	}
	defer conn.Close()

	c := scannerpb.NewAgentServiceClient(conn)

	_, err = c.Heartbeat(ctx, &scannerpb.HeartbeatRequest{Status: "GOOD", Reason: "", Version: "v1.0.0"})
	if err != nil {
		return errors.Wrap(err, "cannot heartbeat")
	}
	return nil
}
