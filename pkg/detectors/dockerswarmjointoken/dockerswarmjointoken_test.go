package dockerswarmjointoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDockerswarmjointoken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid Docker Swarm worker join token",
			input: `
				# To add a worker to this swarm, run the following command:
				docker swarm join --token SWMTKN-1-0p9rh06nzs8dh8qlcj92l879919g79z0i1unndm4ictga70mul-0pkwjoifk8msyd05z99c5l48o 192.168.65.3:2377
			`,
			want: []string{"SWMTKN-1-0p9rh06nzs8dh8qlcj92l879919g79z0i1unndm4ictga70mul-0pkwjoifk8msyd05z99c5l48o"},
		},
		{
			name: "valid Docker Swarm manager join token",
			input: `
				# To add a manager to this swarm, run the following command:
				docker swarm join --token SWMTKN-1-59fl4ak8noy1ay1n2fto7uewqh94cxfq50xwzisspzdtf5wxv3-42qv75gg0pxfpq62gql0n7hfo 192.168.65.3:2377
			`,
			want: []string{"SWMTKN-1-59fl4ak8noy1ay1n2fto7uewqh94cxfq50xwzisspzdtf5wxv3-42qv75gg0pxfpq62gql0n7hfo"},
		},
		{
			name: "Docker Swarm token in environment variable",
			input: `
				export SWARM_JOIN_TOKEN="SWMTKN-1-0d3qxcuv6w6g0zczkd3zn0aer0xb0a8q8kfg4vl1r6bjm7q2jz-7x8f9g5h6j4k3l2m1n0p9o8i7"
			`,
			want: []string{"SWMTKN-1-0d3qxcuv6w6g0zczkd3zn0aer0xb0a8q8kfg4vl1r6bjm7q2jz-7x8f9g5h6j4k3l2m1n0p9o8i7"},
		},
		{
			name: "Docker Swarm token in script",
			input: `
				#!/bin/bash
				JOIN_TOKEN=SWMTKN-1-5bxqnvkqp3uf8xqy9zzh3pwk7mjr2a3fq6sxnvkqp3uf8xqy-9zzh3pwk7mjr2a3fq6sx
				docker swarm join --token $JOIN_TOKEN manager1:2377
			`,
			want: []string{"SWMTKN-1-5bxqnvkqp3uf8xqy9zzh3pwk7mjr2a3fq6sxnvkqp3uf8xqy-9zzh3pwk7mjr2a3fq6sx"},
		},
		{
			name: "invalid pattern - missing second part",
			input: `
				token: SWMTKN-1-3pu6hszjas19xyp7ghgosyx9k8atbfcr8p2is99znpy26u2lkl
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - wrong prefix",
			input: `
				token: SWMKEY-1-3pu6hszjas19xyp7ghgosyx9k8atbfcr8p2is99znpy26u2lkl-1awxwuwd3z9j1z3puu7rcgdbx
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				// For tests that expect no matches (empty want slice), it's OK if keywords are not found
				if len(test.want) > 0 {
					t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
					return
				}
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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
