//go:build detectors
// +build detectors

package datadogapikey

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

func TestDataDogApiKey_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	apiKey := testSecrets.MustGetField("DATADOGTOKEN_TOKEN")
	invalidApiKey := "FKNwdbyfYTmGUm5DK3yHEuK-BBQf0fVG"
	datdogEndpoint := "https://api.us5.datadoghq.com"
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
				data:   []byte(fmt.Sprintf("You can find a datadogtoken secret within datadog %s and endpoint is %v", apiKey, datdogEndpoint)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DatadogApikey,
					Verified:     true,
					AnalysisInfo: map[string]string{
						"apiKey":   apiKey,
						"endpoint": datdogEndpoint,
					},
					Raw: []byte(apiKey),
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a datadogtoken secret within datadog %s and endpoint is %v", invalidApiKey, datdogEndpoint)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DatadogApikey,
					Verified:     false,
					Raw:          []byte(invalidApiKey),
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
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("DatadogToken.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
