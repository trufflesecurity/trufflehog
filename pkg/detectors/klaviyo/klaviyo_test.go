// Pattern tests for the Klaviyo detector.
package klaviyo

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// KlaviyoPatternSuite drives keyPat through the engine's real path (keyword
// prefilter, then FromData). One method per case, so a failure names it.
type KlaviyoPatternSuite struct {
	suite.Suite
	d    Scanner
	core *ahocorasick.Core
}

func TestKlaviyoPatternSuite(t *testing.T) {
	suite.Run(t, new(KlaviyoPatternSuite))
}

// Fresh scanner and prefilter per method, so state can't leak between cases.
func (s *KlaviyoPatternSuite) SetupTest() {
	s.d = Scanner{}
	s.core = ahocorasick.NewAhoCorasickCore([]detectors.Detector{s.d})
}

// Legacy keys must keep matching despite the tighter lowercase-hex rule.
func (s *KlaviyoPatternSuite) TestLegacyHexFormat() {
	key := "pk_a1b2c3d4e5f60718293a4b5c6d7e8f9012" // pk_ + 34 lowercase hex
	input := fmt.Sprintf("klaviyo token = '%s'", key)
	s.Require().NotEmpty(s.core.FindDetectorMatches([]byte(input)), "keyword prefilter should fire")

	results, err := s.d.FromData(context.Background(), false, []byte(input))
	s.Require().NoError(err)
	s.Require().Len(results, 1)
	s.Equal(key, string(results[0].Raw))
}

// The newer prefixed format. Mixed-case company_id is the bit a hex-only
// guess would miss.
func (s *KlaviyoPatternSuite) TestNewPrefixedFormat() {
	key := "pk_AbCdEf_f0e1d2c3b4a5968778695a4b3c2d1e0f00" // pk_ + 6 alnum company_id + _ + 34 hex
	input := fmt.Sprintf("klaviyo token = '%s'", key)
	s.Require().NotEmpty(s.core.FindDetectorMatches([]byte(input)), "keyword prefilter should fire")

	results, err := s.d.FromData(context.Background(), false, []byte(input))
	s.Require().NoError(err)
	s.Require().Len(results, 1)
	s.Equal(key, string(results[0].Raw))
}

// Punctuation in the body should never read as a key.
func (s *KlaviyoPatternSuite) TestPunctuationBodyRejected() {
	results, err := s.d.FromData(context.Background(), false, []byte("klaviyo = 'pk_1234567890abcdefghijklmnopqrstu-_='"))
	s.Require().NoError(err)
	s.Empty(results)
}

// Legacy bodies are lowercase hex (vendor-confirmed), so uppercase is a false
// positive.
func (s *KlaviyoPatternSuite) TestUppercaseHexRejected() {
	results, err := s.d.FromData(context.Background(), false, []byte("klaviyo = 'pk_A1B2C3D4E5F60718293A4B5C6D7E8F9012'"))
	s.Require().NoError(err)
	s.Empty(results)
}

// Guards the legacy {34} length.
func (s *KlaviyoPatternSuite) TestLegacyTooShortRejected() {
	results, err := s.d.FromData(context.Background(), false, []byte("klaviyo = 'pk_a1b2c3d4e5f60718293a4b5c6d7e8f901'")) // 33 hex
	s.Require().NoError(err)
	s.Empty(results)
}

// Guards the new-format {34} tail and trailing \b.
func (s *KlaviyoPatternSuite) TestNewFormatTailTooLongRejected() {
	results, err := s.d.FromData(context.Background(), false, []byte("klaviyo = 'pk_AbCdEf_f0e1d2c3b4a5968778695a4b3c2d1e0f001'")) // 35 hex tail
	s.Require().NoError(err)
	s.Empty(results)
}
