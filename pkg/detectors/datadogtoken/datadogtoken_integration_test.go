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
	inactiveAppKey := testSecrets.MustGetField("DATADOGTOKEN_INACTIVE")

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
				data:   []byte(fmt.Sprintf("You can find a datadogtoken secret %s within datadog %s", appKey, apiKey)),
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
						"apiKey": apiKey,
						"appKey": appKey,
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
				data:   []byte(fmt.Sprintf("You can find a datadogtoken secret %s within but datadog %s not valid", inactiveAppKey, apiKey)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DatadogToken,
					Verified:     false,
					ExtraData: map[string]string{
						"Type": "Application+APIKey",
					},
				},
				{
					DetectorType: detectorspb.DetectorType_DatadogToken,
					Verified:     true,
					ExtraData: map[string]string{
						"Type": "APIKeyOnly",
					},
					AnalysisInfo: map[string]string{
						"apiKey": apiKey,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "api key found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a datadogtoken secret %s", apiKey)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DatadogToken,
					Verified:     true,
					ExtraData: map[string]string{
						"Type": "APIKeyOnly",
					},
					AnalysisInfo: map[string]string{
						"apiKey": apiKey,
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

func TestDatadogToken_AppKeyVerificationFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	s := Scanner{}

	// use default cloud endpoint
	s.UseCloudEndpoint(true)
	s.SetCloudEndpoint(s.CloudEndpoint())
	s.UseFoundEndpoints(true)

	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	apiKey := testSecrets.MustGetField("DATADOGTOKEN_TOKEN")
	appKey := testSecrets.MustGetField("DATADOGTOKEN_APPKEY")

	inputStr := fmt.Sprintf("dd_app:%s\ndd_api_secret:%s", appKey, apiKey)
	got, err := s.FromData(ctx, true, []byte(inputStr))
	if err != nil {
		t.Fatalf("DatadogToken.FromData() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two results, got none")
	}
	result1 := got[0]
	result2 := got[1]

	expectedResult1 := detectors.Result{
		DetectorType: detectorspb.DetectorType_DatadogToken,
		Verified:     false,
		Raw:          []byte(appKey),
		RawV2:        []byte(appKey + apiKey),
		ExtraData: map[string]string{
			"Type": "Application+APIKey",
		},
	}
	expectedResult2 := detectors.Result{
		DetectorType: detectorspb.DetectorType_DatadogToken,
		Verified:     true,
		Raw:          []byte(apiKey),
		RawV2:        []byte(apiKey),
		ExtraData: map[string]string{
			"Type": "APIKeyOnly",
		},
		AnalysisInfo: map[string]string{
			"apiKey": apiKey,
		},
	}

	// Deep compare both structs with their respective results
	if diff := pretty.Compare(result1, expectedResult1); diff != "" {
		t.Errorf("DatadogToken.FromData() result1 diff: (-got +want)\n%s", diff)
	}
	if diff := pretty.Compare(result2, expectedResult2); diff != "" {
		t.Errorf("DatadogToken.FromData() result2 diff: (-got +want)\n%s", diff)
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
