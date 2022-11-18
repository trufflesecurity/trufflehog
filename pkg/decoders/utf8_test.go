package decoders

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestUTF8_FromChunk(t *testing.T) {
	type args struct {
		chunk *sources.Chunk
	}
	tests := []struct {
		name    string
		d       *UTF8
		args    args
		want    *sources.Chunk
		wantErr bool
	}{
		{
			name: "successful UTF8 decode",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("plain 'ol chunk that should decode successfully")},
			},
			want:    &sources.Chunk{Data: []byte("plain 'ol chunk that should decode successfully")},
			wantErr: false,
		},
		{
			name: "successful binary decode",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("\xf0\x28\x8c\x28 not-entirely utf8 chunk that should decode successfully")},
			},
			want:    &sources.Chunk{Data: []byte("( not-entirely utf8 chunk that should decode successfully")},
			wantErr: false,
		},
		{
			name: "unsuccessful decode",
			d:    &UTF8{},
			args: args{
				chunk: nil,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &UTF8{}
			got := d.FromChunk(tt.args.chunk)
			if got != nil && tt.want != nil {
				if diff := pretty.Compare(string(got.Data), string(tt.want.Data)); diff != "" {
					t.Errorf("%s: Plain.FromChunk() diff: (-got +want)\n%s", tt.name, diff)
				}
			} else {
				if diff := pretty.Compare(got, tt.want); diff != "" {
					t.Errorf("%s: Plain.FromChunk() diff: (-got +want)\n%s", tt.name, diff)
				}
			}
		})
	}
}

var testBytes = []byte(`some words   with random spaces and
	
newlines with           
arbitrary length           
of

	hey

the lines themselves.

and
short
words
that
go
away.`)

func Benchmark_extractSubstrings(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractSubstrings(testBytes)
	}
}
