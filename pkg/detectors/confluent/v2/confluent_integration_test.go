//go:build detectors
// +build detectors

package confluent

import (
	"context"
	"fmt"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestConfluent_FromChunk(t *testing.T) {
	// Valid secret with proper CRC32 checksum
	validSecret := "cfltT8d8RzkNseTMEDKcjNM1BZTFPHqRn/dQm9q7w6SjzZ12wZfwjaJdipHZtDjw"
	// Invalid secret with wrong checksum
	invalidSecret := "cfltT8d8RzkNseTMEDKcjNM1BZTFPHqRn/dQm9q7w6SjzZ12wZfwjaJdipHZtDji"

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a confluent secret %s", validSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Confluent,
					Verified:     true,
					ExtraData: map[string]string{
						"rotation_guide": "https://docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/best-practices-api-keys.html#rotate-api-keys-regularly",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a confluent secret %s but not valid", invalidSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Confluent,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/best-practices-api-keys.html#rotate-api-keys-regularly",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Confluent.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Confluent.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
