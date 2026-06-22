package streamio

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestStreamIO_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*1000000000) // 5 seconds
	defer cancel()

	tests := []struct {
		name        string
		input       string
		want        []detectors.Result
		wantErr     bool
		wantMatches int
	}{
		{
			name: "valid stream api key and secret",
			input: `
stream_api_key=abcd1234efgh
stream_api_secret=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
`,
			wantMatches: 1,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_StreamIO,
					Verified:     false,
					SecretParts: map[string]string{
						"api_key":    "abcd1234efgh",
						"api_secret": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
					},
				},
			},
		},
		{
			name: "valid with getstream prefix",
			input: `
getstream_key=testkey12345
getstream_secret=secret1234567890abcdefghijklmnopqrstuvwxyz1234567890
`,
			wantMatches: 1,
		},
		{
			name: "valid in environment variables",
			input: `
STREAM_API_KEY=myapikey123
STREAM_API_SECRET=mysecretkey1234567890abcdefghijklmnopqrstuvwxyz12345
`,
			wantMatches: 1,
		},
		{
			name: "valid in JSON config",
			input: `{
  "stream": {
    "api_key": "streamkey123",
    "api_secret": "streamsecret1234567890abcdefghijklmnopqrstuvwxyz"
  }
}`,
			wantMatches: 1,
		},
		{
			name: "valid in code",
			input: `
const streamApiKey = "appkey12345"
const streamApiSecret = "appsecret1234567890abcdefghijklmnopqrstuvwxyz123"
`,
			wantMatches: 1,
		},
		{
			name: "invalid - key too short",
			input: `
stream_api_key=short
stream_api_secret=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
`,
			wantMatches: 0,
		},
		{
			name: "invalid - secret too short",
			input: `
stream_api_key=validkey123
stream_api_secret=tooshort
`,
			wantMatches: 0,
		},
		{
			name: "invalid - key only without secret",
			input: `
stream_api_key=validkey123
`,
			wantMatches: 0,
		},
		{
			name: "invalid - secret only without key",
			input: `
stream_api_secret=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
`,
			wantMatches: 0,
		},
		{
			name: "multiple valid key-secret pairs",
			input: `
stream_api_key=firstkey123
stream_api_secret=firstsecret1234567890abcdefghijklmnopqrstuvwxyz
stream_api_key=secondkey456
stream_api_secret=secondsecret1234567890abcdefghijklmnopqrstuvwxy
`,
			wantMatches: 4, // 2 keys x 2 secrets = 4 combinations
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(ctx, false, []byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("StreamIO.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.wantMatches {
				t.Errorf("StreamIO.FromData() got %d matches, want %d", len(got), tt.wantMatches)
				return
			}

			if tt.want != nil && len(got) > 0 {
				ignoreOpts := cmpopts.IgnoreUnexported(detectors.Result{})

				if diff := cmp.Diff(got[0].SecretParts, tt.want[0].SecretParts); diff != "" {
					t.Errorf("StreamIO.FromData() SecretParts mismatch (-got +want):\n%s", diff)
				}

				if got[0].DetectorType != tt.want[0].DetectorType {
					t.Errorf("StreamIO.FromData() DetectorType = %v, want %v", got[0].DetectorType, tt.want[0].DetectorType)
				}

				_ = ignoreOpts // ignore unused warning
			}
		})
	}
}

func TestStreamIO_Keywords(t *testing.T) {
	s := Scanner{}
	keywords := s.Keywords()

	if len(keywords) == 0 {
		t.Error("Keywords() returned empty slice")
	}

	expectedKeywords := map[string]bool{
		"stream":    true,
		"getstream": true,
		"stream.io": true,
	}

	for _, kw := range keywords {
		if !expectedKeywords[kw] {
			t.Errorf("unexpected keyword: %s", kw)
		}
	}
}

// TestStreamIO_Pattern tests the regex patterns
func TestStreamIO_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
		matchType   string // "key" or "secret"
	}{
		{
			name:        "valid api key",
			input:       "stream_api_key=abcdef1234",
			shouldMatch: true,
			matchType:   "key",
		},
		{
			name:        "valid api secret",
			input:       "stream_api_secret=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
			shouldMatch: true,
			matchType:   "secret",
		},
		{
			name:        "key with uppercase in value should not match",
			input:       "stream_api_key=ABCDEF1234",
			shouldMatch: false,
			matchType:   "key",
		},
		{
			name:        "key too short",
			input:       "stream_api_key=short",
			shouldMatch: false,
			matchType:   "key",
		},
		{
			name:        "secret too short",
			input:       "stream_api_secret=short",
			shouldMatch: false,
			matchType:   "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matches [][]string
			if tt.matchType == "key" {
				matches = keyPat.FindAllStringSubmatch(tt.input, -1)
			} else {
				matches = secretPat.FindAllStringSubmatch(tt.input, -1)
			}

			matched := len(matches) > 0
			if matched != tt.shouldMatch {
				t.Errorf("Pattern match = %v, want %v for input: %s", matched, tt.shouldMatch, tt.input)
			}
		})
	}
}
