package bcrypthash

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	// Bcrypt hash format: $2a$, $2b$, or $2y$ followed by cost (2 digits) and 53 base64 chars
	// Example: $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
	bcryptPat = regexp.MustCompile(`\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"$2a$", "$2b$", "$2y$", "bcrypt"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_BcryptHash
}

func (s Scanner) Description() string {
	return "Bcrypt hashes found in code may indicate leaked password hashes or authentication credentials. While bcrypt is a secure hashing algorithm, exposed hashes can be targeted by attackers."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range bcryptPat.FindAllString(dataStr, -1) {
		uniqueMatches[strings.TrimSpace(match)] = struct{}{}
	}

	for hash := range uniqueMatches {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(hash),
			SecretParts: map[string]string{
				"hash": hash,
			},
			ExtraData: map[string]string{
				"info": "Bcrypt hash detected. Ensure this is not a leaked password hash.",
			},
		}

		// Bcrypt hashes cannot be verified without the original password
		// They are one-way hashes, so we just flag them as found
		r.Verified = false

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}
