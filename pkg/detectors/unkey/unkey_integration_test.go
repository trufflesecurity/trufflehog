//go:build detectors
// +build detectors

package unkey

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestUnkey_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Pattern only. Both values of verify report the key as unverified and
	// set no verification error. There is no remote call to time out.
	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, unverified when verification is requested",
			s:    Scanner{},
			args: args{
				ctx:    ctx,
				data:   []byte("You can find an unkey root key " + fixtureKey + " within"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Unkey,
					Verified:     false,
					SecretParts:  map[string]string{"key": fixtureKey},
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified when verification is not requested",
			s:    Scanner{},
			args: args{
				ctx:    ctx,
				data:   []byte("You can find an unkey root key " + fixtureKey + " within"),
				verify: false,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Unkey,
					Verified:     false,
					SecretParts:  map[string]string{"key": fixtureKey},
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, checksum mismatch is not a result",
			s:    Scanner{},
			args: args{
				ctx:    ctx,
				data:   []byte("unkeyv1 " + fixtureKey[:len(fixtureKey)-1] + "9"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    ctx,
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unkey.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			// Ignore unexported result fields. Raw is checked above for presence
			// and compared through SecretParts.
			ignoreOpts := cmp.Options{
				cmpopts.IgnoreUnexported(detectors.Result{}),
				cmpopts.IgnoreFields(detectors.Result{}, "Raw"),
			}
			if diff := cmp.Diff(tt.want, got, ignoreOpts); diff != "" {
				t.Errorf("Unkey.FromData() %s diff: (-want +got)\n%s", tt.name, diff)
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
