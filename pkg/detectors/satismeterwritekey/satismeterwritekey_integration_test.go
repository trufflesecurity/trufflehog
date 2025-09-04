//go:build detectors
// +build detectors

package satismeterwritekey

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestSatismeterWritekey_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors3")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	projectID := testSecrets.MustGetField("SATISMETERPROJECTKEY")
	inactiveProjectID := testSecrets.MustGetField("SATISMETERPROJECTKEY_INACTIVE")
	token := testSecrets.MustGetField("SATISMETER_TOKEN")
	inactiveToken := testSecrets.MustGetField("SATISMETER_TOKEN_INACTIVE")
	writeKey := testSecrets.MustGetField("SATISMETER_WRITEKEY")
	inactiveWriteKey := testSecrets.MustGetField("SATISMETER_WRITEKEY_INACTIVE")

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
				data:   []byte(fmt.Sprintf("You can find a satismeterwritekey project %s satismeter writekey %s and satismeter token %s in here", projectID, writeKey, token)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SatismeterWritekey,
					Verified:     false,
					RawV2:        []byte(projectID + token),
				},
				{
					DetectorType: detectorspb.DetectorType_SatismeterWritekey,
					Verified:     true,
					RawV2:        []byte(projectID + writeKey),
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a satismeterwritekey project %s satismeter writekey %s and satismeter token %s in here but not valid", inactiveProjectID, inactiveWriteKey, inactiveToken)), // the secret would satisfy the regex but not pass validation,
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_SatismeterWritekey,
					Verified:     false,
					RawV2:        []byte(inactiveProjectID + inactiveToken),
				},
				{
					DetectorType: detectorspb.DetectorType_SatismeterWritekey,
					Verified:     false,
					RawV2:        []byte(inactiveProjectID + inactiveWriteKey),
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
				t.Errorf("SatismeterWritekey.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("SatismeterWritekey.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
