package aiven

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAiven_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Sending request to the aiven API
				[DEBUG] Using Key = yb+Ygm82FfUworm2exB+Uk255p0uQKmmfx4ut1KfsZ3YI3Gp2xPYyxZgrwYabMxXXO4WPsK7xlLJRy0BWIpM2SKnzA2p69P8aOmYbl24ZiVGlLXyQxeVDDy7gru5Yzt=Y1UDLBpsW=hhGIKsrPgc/7hpxuEfEqbXJe5IBYO484F+ekaTmYN4nTF94O==3WuG+WuSW7zaYzXH1V==kZFj07zBtmShS0z/lW=N3HipH=oJjXI2pyFxU+A7vM9yHdUHoiZEOVoWsyp5zO1ajBOqFr=3jIIaXWmbH33dP2ZNQFJhqbeg6JlXA9GpfMFht5=ZCC1IirWCNp=UILbmZtvu9d2M8U0YNHwAGKtjrPS5lZvAU+W5s2Ti
				[INFO] Response received: 200 OK
			`,
			want: []string{"yb+Ygm82FfUworm2exB+Uk255p0uQKmmfx4ut1KfsZ3YI3Gp2xPYyxZgrwYabMxXXO4WPsK7xlLJRy0BWIpM2SKnzA2p69P8aOmYbl24ZiVGlLXyQxeVDDy7gru5Yzt=Y1UDLBpsW=hhGIKsrPgc/7hpxuEfEqbXJe5IBYO484F+ekaTmYN4nTF94O==3WuG+WuSW7zaYzXH1V==kZFj07zBtmShS0z/lW=N3HipH=oJjXI2pyFxU+A7vM9yHdUHoiZEOVoWsyp5zO1ajBOqFr=3jIIaXWmbH33dP2ZNQFJhqbeg6JlXA9GpfMFht5=ZCC1IirWCNp=UILbmZtvu9d2M8U0YNHwAGKtjrPS5lZvAU+W5s2Ti"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{aiven}</id>
  					<secret>{aiven AQAAABAAA IGhXNR6g7rogABp/H2iDQu7TgkXpvn9KnwzJfeh+8p7M=JVsI2QoQ38mmQHt450bQC4wBOGFhV+9QT2KGWSMfTOxTUrUXygaLlwsXo/RBxKXyOdh=/L8EGGrqG6=qbd0UzDAfc0xeAfXd30RGj+Ypsrrvdda=ZPa32BBID5r2ClfJSbgpfWIpVC1b5vlqCdy5LIWABZJzjBC5VweqZ04XFaCh+15NuSQ4E0KdGwPdkrfxxjY20I1wDvlKxzxL7dfCly3KVlQv7KBEFSLaLRNRocPYToUXqU4yAXKvXf03K=k1mahpxFUp94c35k/n055LVs=xbyL6AKdW=sCCa1AFIYKBDMBprTsZ6Al7DHx=XA6qLNWYxS7}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"IGhXNR6g7rogABp/H2iDQu7TgkXpvn9KnwzJfeh+8p7M=JVsI2QoQ38mmQHt450bQC4wBOGFhV+9QT2KGWSMfTOxTUrUXygaLlwsXo/RBxKXyOdh=/L8EGGrqG6=qbd0UzDAfc0xeAfXd30RGj+Ypsrrvdda=ZPa32BBID5r2ClfJSbgpfWIpVC1b5vlqCdy5LIWABZJzjBC5VweqZ04XFaCh+15NuSQ4E0KdGwPdkrfxxjY20I1wDvlKxzxL7dfCly3KVlQv7KBEFSLaLRNRocPYToUXqU4yAXKvXf03K=k1mahpxFUp94c35k/n055LVs=xbyL6AKdW=sCCa1AFIYKBDMBprTsZ6Al7DHx=XA6qLNWYxS7"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
				[DEBUG] aiven api processing
				[INFO] Sending request to the API
				[DEBUG] Using Key=yb+Ygm82FfUworm2exB+Uk255p0uQKmmfx4ut1KfsZ3YI3Gp2xPYyxZgrwYabMxXXO4WPsK7xlLJRy0BWIpM2SKnzA2p69P8aOmYbl24ZiVGlLXyQxeVDDy7gru5Yzt=Y1UDLBpsW=hhGIKsrPgc/7hpxuEfEqbXJe5IBYO484F+ekaTmYN4nTF94O==3WuG+WuSW7zaYzXH1V==kZFj07zBtmShS0z/lW=N3HipH=oJjXI2pyFxU+A7vM9yHdUHoiZEOVoWsyp5zO1ajBOqFr=3jIIaXWmbH33dP2ZNQFJhqbeg6JlXA9GpfMFht5=ZCC1IirWCNp=UILbmZtvu9d2M8U0YNHwAGKtjrPS5lZvAU+W5s2Ti
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the aiven API
				[DEBUG] Using Key=SSs8PGhwqWzb4qfqiwLV/bNHfiQ2VSKyX88AAYm3+CGHbTe/FYXRNOYYHO=PXwuL/GftiES7j8ffzWW9p1dAyNc6hZZpoazmd+Vf1kbukZSL8QO/LdKFI/YFlupu0dELqQVHeZi/cJlnp6aQeY7zIJiHhJS51ZVdOamc=zOUMebry3BYOo2LhYIz+mLND7s5/cHZZpkEvTXrKnVf4vdYMl+fawv84AYCTo9pry8FQBsqRex2HL98kAiqhVYG+nLyRz/hZCo8owaRkzli1BUT4O63TSKJIgnECOBvyZz7o+yX92BhDe+B2Tllk3y2=qG5TiEl2sCJI8V5GJ1cz52RpXx2hVXMi=1Zl5CHpX8Adr9VMbj$Co
				[ERROR] Response received: 401 UnAuthorized
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
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
