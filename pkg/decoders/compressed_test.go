package decoders

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestCompressed_FromChunk(t *testing.T) {
	tests := []struct {
		chunk *sources.Chunk
		want  *sources.Chunk
		name  string
	}{
		{
			name: "only commpressed chunk",
			chunk: &sources.Chunk{
				Data: []byte{31, 139, 8, 0, 59, 55, 156, 100, 0, 3, 203, 201, 207, 75, 79, 45, 210, 77, 205, 75, 206, 79, 73, 77, 209, 45, 78, 77, 46, 74, 45, 209, 45, 73, 45, 46, 1, 0, 13, 210, 72, 54, 26, 0, 0, 0},
			},
			want: &sources.Chunk{
				Data: []byte(`longer-encoded-secret-test`),
			},
		},
		{
			name: "no chunk",
			chunk: &sources.Chunk{
				Data: []byte(``),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Compressed{}
			got := d.FromChunk(tt.chunk)
			if tt.want != nil {
				if got == nil {
					t.Fatal("got nil, did not want nil")
				}
				if diff := pretty.Compare(string(got.Data), string(tt.want.Data)); diff != "" {
					t.Errorf("CompressedFromChunk() %s diff: (-got +want)\n%s", tt.name, diff)
				}
			} else {
				if got != nil {
					t.Error("Expected nil chunk")
				}
			}
		})
	}
}
