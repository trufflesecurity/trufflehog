package dockerswarmjointoken

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Docker Swarm join tokens have the format: SWMTKN-1-<base64>-<base64>
	// The base64 parts contain alphanumeric characters, hyphens, and underscores
	keyPat = regexp.MustCompile(`\b(SWMTKN-1-[0-9a-zA-Z]{40,}-[0-9a-zA-Z]{20,})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"SWMTKN"}
}

// FromData will find Docker Swarm join tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DockerSwarmJoinToken,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"token": match},
		}

		// Docker Swarm join tokens cannot be verified remotely
		// They can only be used when joining a node to a swarm cluster
		// The token itself doesn't provide an API endpoint for verification
		s1.Verified = false

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DockerSwarmJoinToken
}

func (s Scanner) Description() string {
	return "Docker Swarm join tokens are used to authenticate nodes when joining a Docker Swarm cluster. These tokens grant either worker or manager permissions depending on the token type."
}
