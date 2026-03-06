package ldap

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	ldap "github.com/mariduv/ldap-verify"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validUriPattern        = "ldaps://127.0.0.1:389"
	invalidUriPattern      = "idaps://127.0.0.1:389"
	validUsernamePattern   = "cCOfHuyrVdDdcWCAbKLCSAlospWAdCmfKwr="
	invalidUsernamePattern = "0fHuy2VdDdcWCAbKLC412lospWAdCmfKwr9="
	validPasswordPattern   = "A:J$NL9~6:u:L$_:VO4tf))h#v0i}O"
	invalidPasswordPattern = "A:J$NL9~6:u:L$_:VO4tf))h#v0i}O"
	validIadPattern        = "OpenDSObject(\"ldaps://www\", \"ABC\", \"XYZ\", 123)"
	invalidIadPattern      = "OpenDSObject(\"ldaps://www\", \"ABC\", \"XYZ\", ?)"
)

func TestLdap_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("%s bind '%s' pass '%s' %s", validUriPattern, validIadPattern, validPasswordPattern, validUsernamePattern),
			want:  []string{"ldaps://www\tABC\tXYZ"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = bind '%s' pass '%s %s", invalidUriPattern, invalidUsernamePattern, invalidPasswordPattern, invalidIadPattern),
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

func Test_isErrDeterminate(t *testing.T) {
	if isErrDeterminate(fmt.Errorf("anything")) != true {
		t.Errorf("general errors should be determinate")
	}

	if isErrDeterminate(&ldap.Error{Err: fmt.Errorf("anything")}) != true {
		t.Errorf("ldap general errors should be determinate")
	}

	if isErrDeterminate(&ldap.Error{Err: &net.OpError{}}) == true {
		t.Errorf("ldap net.OpError{} should be indeterminate")
	}

	if isErrDeterminate(&ldap.Error{Err: context.DeadlineExceeded}) == true {
		t.Errorf("ldap context deadline should be indeterminate")
	}

	if isErrDeterminate(&ldap.Error{Err: context.Canceled}) == true {
		t.Errorf("ldap context deadline should be indeterminate")
	}
}
