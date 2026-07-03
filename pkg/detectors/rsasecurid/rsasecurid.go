package rsasecurid

import (
	"context"
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Compile-time interface check.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// snPat matches the <SN> serial-number element of an RSA SecurID .sdtid token.
	// SecurID token serial numbers are 12 digits.
	snPat = regexp.MustCompile(`<SN>\s*(\d{12})\s*</SN>`)

	// seedPat matches the <Seed> element holding the token's TOTP seed. The seed is
	// either a 128-bit value in hex (32 chars) or, more commonly in distributed
	// .sdtid files, the AES-encrypted seed in base64. We require 16+ chars to reject
	// short false positives while accepting both encodings.
	seedPat = regexp.MustCompile(`<Seed>\s*([A-Za-z0-9+/]{16,}={0,2})\s*</Seed>`)

	// contextPat requires a structural marker of an RSA SecurID token export so
	// that generic XML containing unrelated <SN>/<Seed> elements is not reported.
	contextPat = regexp.MustCompile(`(?i)<TKNBatch|<TKNBasic|\.sdtid`)
)

// Keywords returns the strings used by the Aho-Corasick prefilter. Every
// structural marker recognised by contextPat (<TKNBatch>, <TKNBasic> and the
// .sdtid extension) must be represented here, otherwise a token carrying only
// one of those markers is dropped by the prefilter before FromData ever runs.
// The <TKNBatch>/<TKNBasic> elements and the .sdtid extension are highly
// distinctive of RSA SecurID software-token export files. Matching is
// case-insensitive.
func (s Scanner) Keywords() []string {
	return []string{"TKNBatch", "TKNBasic", "sdtid"}
}

// FromData scans for RSA SecurID software token credentials. A token is only
// reported when both a 12-digit serial number (<SN>) and a TOTP seed (<Seed>)
// are present, which together are sufficient to reconstruct one-time codes.
// There is no public endpoint to validate a software token, so results are
// emitted unverified.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Require an RSA SecurID structural marker; reject generic XML that merely
	// happens to contain <SN>/<Seed> elements.
	if !contextPat.MatchString(dataStr) {
		return nil, nil
	}

	serials := make(map[string]struct{})
	for _, match := range snPat.FindAllStringSubmatch(dataStr, -1) {
		serials[match[1]] = struct{}{}
	}
	if len(serials) == 0 {
		return nil, nil
	}

	seeds := make(map[string]struct{})
	for _, match := range seedPat.FindAllStringSubmatch(dataStr, -1) {
		seeds[match[1]] = struct{}{}
	}
	if len(seeds) == 0 {
		return nil, nil
	}

	for serial := range serials {
		for seed := range seeds {
			result := detectors.Result{
				DetectorType: detector_typepb.DetectorType_RSASecurID,
				Raw:          []byte(seed),
				RawV2:        []byte(fmt.Sprintf("%s:%s", serial, seed)),
				SecretParts: map[string]string{
					"serial": serial,
					"seed":   seed,
				},
			}
			// RSA SecurID software tokens cannot be validated against a public
			// API, so verification is not supported.
			_ = verify

			results = append(results, result)
		}
	}

	return results, nil
}

// Type returns the detector enum value for RSA SecurID software tokens.
func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_RSASecurID
}

// Description returns a human-readable description of what this detector finds.
func (s Scanner) Description() string {
	return "RSA SecurID software tokens (.sdtid files) contain a token serial number (SN) and a TOTP " +
		"seed (Seed). Possession of the seed allows an attacker to generate valid one-time passcodes " +
		"and impersonate the token holder during multi-factor authentication."
}
