//go:build detectors
// +build detectors

package datadogtoken

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDatadogToken_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	apiKey := testSecrets.MustGetField("DATADOGTOKEN_TOKEN")
	appKey := testSecrets.MustGetField("DATADOGTOKEN_APPKEY")
	endpoint := "https://api.us5.datadoghq.com"

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
				data:   []byte(fmt.Sprintf("You can find a datadogtoken secret %s within datadog %s and endpoint %s", appKey, apiKey, endpoint)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DatadogToken,
					Verified:     true,
					ExtraData: map[string]string{
						"Type": "Application+APIKey",
					},
					AnalysisInfo: map[string]string{
						"apiKey":   apiKey,
						"appKey":   appKey,
						"endpoint": endpoint,
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

			// use default cloud endpoint
			s.UseCloudEndpoint(true)
			s.SetCloudEndpoint(s.CloudEndpoint())
			s.UseFoundEndpoints(true)

			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DatadogToken.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
				got[i].RawV2 = nil
				delete(got[i].ExtraData, "user_emails")
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("DatadogToken.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestDatadogToken_FromChunk_Unverified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	apiKey := testSecrets.MustGetField("DATADOGTOKEN_TOKEN")
	inactiveAppKey := testSecrets.MustGetField("DATADOGTOKEN_INACTIVE")

	data := []byte(fmt.Sprintf(
		"You can find a datadogtoken secret %s within but datadog %s not valid",
		inactiveAppKey,
		apiKey,
	))

	s := Scanner{}
	s.UseCloudEndpoint(true)
	s.SetCloudEndpoint(s.CloudEndpoint())
	s.UseFoundEndpoints(true)

	results, err := s.FromData(ctx, true, data)
	if err != nil {
		t.Fatalf("FromData returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]

	if r.DetectorType != detectorspb.DetectorType_DatadogToken {
		t.Errorf("unexpected detector type: %v", r.DetectorType)
	}

	if r.Verified {
		t.Errorf("expected token to be unverified")
	}

	if r.VerificationError() == nil {
		t.Errorf("Expected verification error")
	}

	if got := r.ExtraData["Type"]; got != "Application+APIKey" {
		t.Errorf("unexpected ExtraData Type: %q", got)
	}

	if len(r.Raw) == 0 {
		t.Errorf("expected raw secret to be present")
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
