package storychief

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "OjhRmEboKs5kYVWJOrpTrloSRsAdkEl8PK-eHrSID5TRR.59-m5ezCY1dcJqJCxbV.2.LeGuqnhuouYkaiJ-iq90X-XX0J3IcT-ReLn.lAU0FfkvHOoOFp4k8w0-nDKAI8irzT5.pi7bmathhUdZO40-Rb59B6M0h40LbAkcvW49YP_-xXqGV_s.tCRbbzeUWt.Y9cFzfrQfRaVlTTqF5AC4mTEF4UxCSHK7uEE3OdzKhRehslviyKozUqer9HEZQ941rCqeEpt8kDcC0GOZFskrqu-EynCRJRhK6cv682e3HoRqE9x5FtcJ3gPfJEA70yHF5gTT0gh1KYDPKoJ-SQ7cjEBxxn-NbLu_WD3HW8DsjVDu1MgqrjqrnFNQvEAqYM7RI.RurVC38TP-5PioJqzJbvpNzkvwFjDrPpHdcivLgDEJUXS39PkIZPb1WCk.LPMOj5MBAwgn7TuADlV34Tael2FxygTPzA6ZVHBzm4aoUZ94Fwcm1vAkKJPeydsu33lmJ73e55pp7IhFyRO6MdPgLHqm3XkUhleU4yDUAEPWMyhilzOEO1t3nP3plfPjZU1.A1VEgWoOjvhs61qAMj2O6YsVFc7nU-PRlOpqj7yJNRmLWnJGVZW1UQLYwo5urJTb92u8BBPe179Eldzk5-xQ994NnrROnAK5DXkwdw9KII85fVBof8LGei1ocVEzYodTVvVY75iXaVmIP3Sf3dqkumW9Jdik-G-Lz.tvyJMTUSmtbX1oXaByyInng89h0Ah1O7D36nUm-gSOOgjJAssWCF0jiOSb2ps7BCdArjd5BVEOhewpodrtDs.iOncs8dtMSmyA5N7Jhzo2eINenb9dhJ7yQmskzhQcN-jpHKLpiL.w4lqCZ5X.uI_oDjx6V_7bJQK07uWCEB8xiwTRCCnB0mZYmi5q0WpG4sCY2xIW"
	invalidPattern = "O?hRmEboKs5kYVWJOrpTrloSRsAdkEl8PK-eHrSID5TRR.59-m5ezCY1dcJqJCxbV.2.LeGuqnhuouYkaiJ-iq90X-XX0J3IcT-ReLn.lAU0FfkvHOoOFp4k8w0-nDKAI8irzT5.pi7bmathhUdZO40-Rb59B6M0h40LbAkcvW49YP_-xXqGV_s.tCRbbzeUWt.Y9cFzfrQfRaVlTTqF5AC4mTEF4UxCSHK7uEE3OdzKhRehslviyKozUqer9HEZQ941rCqeEpt8kDcC0GOZFskrqu-EynCRJRhK6cv682e3HoRqE9x5FtcJ3gPfJEA70yHF5gTT0gh1KYDPKoJ-SQ7cjEBxxn-NbLu_WD3HW8DsjVDu1MgqrjqrnFNQvEAqYM7RI.RurVC38TP-5PioJqzJbvpNzkvwFjDrPpHdcivLgDEJUXS39PkIZPb1WCk.LPMOj5MBAwgn7TuADlV34Tael2FxygTPzA6ZVHBzm4aoUZ94Fwcm1vAkKJPeydsu33lmJ73e55pp7IhFyRO6MdPgLHqm3XkUhleU4yDUAEPWMyhilzOEO1t3nP3plfPjZU1.A1VEgWoOjvhs61qAMj2O6YsVFc7nU-PRlOpqj7yJNRmLWnJGVZW1UQLYwo5urJTb92u8BBPe179Eldzk5-xQ994NnrROnAK5DXkwdw9KII85fVBof8LGei1ocVEzYodTVvVY75iXaVmIP3Sf3dqkumW9Jdik-G-Lz.tvyJMTUSmtbX1oXaByyInng89h0Ah1O7D36nUm-gSOOgjJAssWCF0jiOSb2ps7BCdArjd5BVEOhewpodrtDs.iOncs8dtMSmyA5N7Jhzo2eINenb9dhJ7yQmskzhQcN-jpHKLpiL.w4lqCZ5X.uI_oDjx6V_7bJQK07uWCEB8xiwTRCCnB0mZYmi5q0WpG4sCY2xIW"
	keyword        = "storychief"
)

func TestStorychief_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword storychief",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
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
