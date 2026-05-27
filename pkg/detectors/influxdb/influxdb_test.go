package influxdb

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestInfluxDB_FromData(t *testing.T) {
	token := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abc=="

	tests := []struct {
		name string
		data []byte
		want []detectors.Result
	}{
		{
			name: "env influx token",
			data: []byte(`INFLUX_TOKEN="` + token + `"`),
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_InfluxDB,
				},
			},
		},
		{
			name: "influxdb api token",
			data: []byte(`influxdb_api_token: ` + token),
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_InfluxDB,
				},
			},
		},
		{
			name: "datasource token",
			data: []byte(`DATASOURCE_INFLUXDB_TOKEN=` + token),
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_InfluxDB,
				},
			},
		},
		{
			name: "deduplicates repeated token",
			data: []byte("INFLUX_TOKEN=" + token + "\nINFLUXDB_TOKEN=" + token),
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_InfluxDB,
				},
			},
		},
		{
			name: "ignores long random value without token context",
			data: []byte(`value="` + token + `"`),
			want: nil,
		},
		{
			name: "ignores short token-like value",
			data: []byte(`INFLUX_TOKEN="short-token"`),
			want: nil,
		},
	}

	s := Scanner{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.FromData(context.Background(), false, tt.data)
			if err != nil {
				t.Fatalf("InfluxDB.FromData() error = %v", err)
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "SecretParts")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("InfluxDB.FromData() diff: (-got +want)\n%s", diff)
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
