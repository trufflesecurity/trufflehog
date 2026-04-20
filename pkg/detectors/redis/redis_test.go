package redis

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKey          = "redis://1SHPg6BjyS:$YYbMDot25P@PvfdX9VshFjW"
	invalidKey        = "redis://1SHPg6BjySX$YYbMDot25P@PvfdX9VshFjW"
	validDomain       = "QZc67koZ6rUV.redis.cache.windows.net:6380"
	invalidDomain     = "QZc67koZ6rUV.redis.cache.windows.net:6381"
	password          = "Xcc3S9d7And6aMdfOcUc0acHJh3CiDh3l9DsapNwGwyS"
	validAzureRedis   = validDomain + ",password=" + password + ",ssl=True,abortConnect=False"
	invalidAzureRedis = invalidDomain + ",password=" + password + ",ssl=False,abortConnect=True"
	keyword           = "redis"
)

func TestRedis_ExtraData(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		wantHost     string
		wantUsername string
	}{
		{
			name:         "standard redis URI",
			data:         `redis://myuser:mysecretpass@redis.example.com:6379/0`,
			wantHost:     "redis.example.com:6379",
			wantUsername: "myuser",
		},
		{
			name:         "redis URI with default username",
			data:         `redis://default:mysecretpass@redis.example.com:6379`,
			wantHost:     "redis.example.com:6379",
			wantUsername: "default",
		},
		{
			name:     "azure redis pattern without username",
			data:     `mycache.redis.cache.windows.net:6380,password=Xcc3S9d7And6aMdfOcUc0acHJh3CiDh3l9DsapNwGwyS,ssl=True,abortConnect=False`,
			wantHost: "mycache.redis.cache.windows.net:6380",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			results, err := s.FromData(context.Background(), false, []byte(tt.data))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) == 0 {
				t.Fatal("expected at least one result")
			}
			r := results[0]
			if got := r.ExtraData["host"]; got != tt.wantHost {
				t.Errorf("ExtraData[host] = %q, want %q", got, tt.wantHost)
			}
			if tt.wantUsername != "" {
				if got := r.ExtraData["username"]; got != tt.wantUsername {
					t.Errorf("ExtraData[username] = %q, want %q", got, tt.wantUsername)
				}
			} else {
				if got, ok := r.ExtraData["username"]; ok {
					t.Errorf("ExtraData[username] should be absent, got %q", got)
				}
			}
		})
	}
}

func TestRedisIntegration_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword redis",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validKey, keyword, validAzureRedis),
			want:  []string{"rediss://:" + password + "@" + validDomain},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidKey, keyword, invalidAzureRedis),
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
