package arweavekey

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Compile-time interface check.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// ktyRSAPat matches the "kty":"RSA" JSON field (with optional whitespace).
	ktyRSAPat = regexp.MustCompile(`"kty"\s*:\s*"RSA"`)

	// dFieldPat matches the "d" field (RSA private exponent) encoded in base64url.
	// Arweave wallet private exponents are ~342 base64url chars; we require 100+ to
	// exclude obviously short/fake values while allowing variation in key size.
	dFieldPat = regexp.MustCompile(`"d"\s*:\s*"([A-Za-z0-9_-]{100,})"`)
)

// Keywords returns the strings used by the Aho-Corasick prefilter.
// Either "kty" (present in any JWK) or "arweave" (explicit mention) triggers the detector.
func (s Scanner) Keywords() []string {
	return []string{"kty", "arweave"}
}

// FromData scans for Arweave RSA JWK private keys in the provided data.
// An Arweave wallet key is a JSON Web Key with "kty":"RSA" and a "d" field
// containing the RSA private exponent in base64url encoding.
// No live API verification is available for Arweave wallet keys.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Both the RSA key type marker and the private exponent must be present.
	if !ktyRSAPat.MatchString(dataStr) {
		return nil, nil
	}

	uniqueKeys := make(map[string]struct{})
	for _, match := range dFieldPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[match[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_ArweaveKey,
			Raw:          []byte(key),
			SecretParts: map[string]string{
				"d": key,
			},
		}
		// Arweave does not expose a REST endpoint that accepts raw JWK keys for
		// validation, so verification is not supported.
		_ = verify

		results = append(results, result)
	}

	return
}

// Type returns the detector enum value for Arweave wallet private keys.
func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ArweaveKey
}

// Description returns a human-readable description of what this detector finds.
func (s Scanner) Description() string {
	return "Arweave wallet private keys are RSA JSON Web Keys (JWK) containing the private exponent " +
		"'d' field in base64url encoding. Exposure allows full control of the associated Arweave " +
		"wallet and all AR tokens held within it."
}
