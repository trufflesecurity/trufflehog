package decoders

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestBase64_FromChunk(t *testing.T) {
	tests := []struct {
		name  string
		chunk *sources.Chunk
		want  *sources.Chunk
	}{
		{
			name: "only b64 chunk",
			chunk: &sources.Chunk{
				Data: []byte(`bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`),
			},
			want: &sources.Chunk{
				Data: []byte(`longer-encoded-secret-test`),
			},
		},
		{
			name: "mixed content",
			chunk: &sources.Chunk{
				Data: []byte(`token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`),
			},
			want: &sources.Chunk{
				Data: []byte(`token: longer-encoded-secret-test`),
			},
		},
		{
			name: "no chunk",
			chunk: &sources.Chunk{
				Data: []byte(``),
			},
			want: nil,
		},
		{
			name: "env var (looks like all b64 decodable but has `=` in the middle)",
			chunk: &sources.Chunk{
				Data: []byte(`some-encoded-secret=dGVzdHNlY3JldA==`),
			},
			want: &sources.Chunk{
				Data: []byte(`some-encoded-secret=testsecret`),
			},
		},
		{
			name: "has longer b64 inside",
			chunk: &sources.Chunk{
				Data: []byte(`some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="`),
			},
			want: &sources.Chunk{
				Data: []byte(`some-encoded-secret="longer-encoded-secret-test"`),
			},
		},
		{
			name: "many possible substrings",
			chunk: &sources.Chunk{
				Data: []byte(`Many substrings in this slack message could be base64 decoded
				but only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded.`),
			},
			want: &sources.Chunk{
				Data: []byte(`Many substrings in this slack message could be base64 decoded
				but only this encapsulated secret should be decoded.`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Base64{}
			got := d.FromChunk(tt.chunk)
			if tt.want != nil {
				if got == nil {
					t.Fatal("got nil, did not want nil")
				}
				if diff := pretty.Compare(string(got.Data), string(tt.want.Data)); diff != "" {
					t.Errorf("Base64FromChunk() %s diff: (-got +want)\n%s", tt.name, diff)
				}
			} else {
				if got != nil {
					t.Error("Expected nil chunk")
				}
			}
		})
	}
}

func BenchmarkFromChunk(benchmark *testing.B) {
	d := Base64{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				d.FromChunk(&sources.Chunk{Data: data})
			}
		})
	}
}
