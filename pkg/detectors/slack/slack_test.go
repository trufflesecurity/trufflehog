//go:build detectors
// +build detectors

package slack

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

func TestScanner_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("SLACK")
	secretInactive := testSecrets.MustGetField("SLACK_INACTIVE")
	tests := []struct {
		name        string
		data        []byte
		verify      bool
		wantResults []detectors.Result
		wantErr     bool
	}{
		{
			name:   "found, verified",
			data:   []byte(fmt.Sprintf("You can find a slack secret %s within", secret)),
			verify: true,
			wantResults: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Slack,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name:   "found but unverified",
			data:   []byte(fmt.Sprintf("You can find a slack secret %s within", secretInactive)),
			verify: true,
			wantResults: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Slack,
					Verified:     false,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(context.Background(), tt.verify, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Scanner.FromData) error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.wantResults); diff != "" {
				t.Errorf("Scanner.FromData) %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
