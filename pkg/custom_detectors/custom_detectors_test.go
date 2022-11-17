package custom_detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/protoyaml"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const testYamlConfig = `name: Internal bi tool
type: DETECTOR_TYPE_REGEX
connection:
  '@type': type.googleapis.com/custom_detectors.CustomRegex
  keywords:
  - secret_v1_
  - pat_v2_
  regex:
    id_pat_example: ([a-zA-Z0-9]{32})
    secret_pat_example: ([a-zA-Z0-9]{32})
  verify:
  - endpoint: http://localhost:8000/{id_pat_example}
    unsafe: true
    headers:
    - 'Authorization: Bearer {secret_pat_example.0}'
    successRanges:
    - 200-250
    - '288'`

func TestYamlParsing(t *testing.T) {
	var message custom_detectorspb.CustomDetector

	assert.NoError(t, protoyaml.UnmarshalStrict([]byte(testYamlConfig), &message))
	assert.Equal(t, "Internal bi tool", message.Name)
	assert.Equal(t, "DETECTOR_TYPE_REGEX", message.Type)

	// unmarshall as regex type
	var conn custom_detectorspb.CustomRegex
	assert.NoError(t, anypb.UnmarshalTo(message.Connection, &conn, proto.UnmarshalOptions{}))
	assert.Equal(t, []string{"secret_v1_", "pat_v2_"}, conn.Keywords)
	assert.Equal(t, map[string]string{
		"id_pat_example":     "([a-zA-Z0-9]{32})",
		"secret_pat_example": "([a-zA-Z0-9]{32})",
	}, conn.Regex)
	assert.Equal(t, []*custom_detectorspb.VerifierConfig{{
		Endpoint:      "http://localhost:8000/{id_pat_example}",
		Unsafe:        true,
		Headers:       []string{"Authorization: Bearer {secret_pat_example.0}"},
		SuccessRanges: []string{"200-250", "288"},
	}}, conn.Verify)
}
