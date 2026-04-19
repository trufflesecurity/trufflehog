package sources_test

import (
	"reflect"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/circleci"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/docker"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/elasticsearch"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/filesystem"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/gcs"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/git"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/github"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/gitlab"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/huggingface"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/jenkins"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/postman"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/s3"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/syslog"
)

// TestRegistryComplete asserts every source the overhaul is expected to
// register actually registered. If this fails it's almost always because a
// source package wasn't blank-imported by pkg/tui/tui.go.
func TestRegistryComplete(t *testing.T) {
	want := []string{
		"circleci", "docker", "elasticsearch", "filesystem",
		"gcs", "git", "github", "gitlab",
		"huggingface", "jenkins", "postman", "s3", "syslog",
	}
	for _, id := range want {
		if _, ok := sources.Get(id); !ok {
			t.Errorf("source %q not registered", id)
		}
	}
}

func TestFormAdapterArgs(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		values map[string]string
		want   []string
	}{
		{
			name:   "git positional",
			id:     "git",
			values: map[string]string{"uri": "file:///tmp/my repo"},
			want:   []string{"git", "file:///tmp/my repo"},
		},
		{
			name: "github org",
			id:   "github",
			values: map[string]string{
				"org": "trufflesecurity",
			},
			want: []string{"github", "--org=trufflesecurity"},
		},
		{
			name:   "filesystem positional with spaces",
			id:     "filesystem",
			values: map[string]string{"path": "/tmp/path with spaces"},
			want:   []string{"filesystem", "/tmp/path with spaces"},
		},
		{
			name:   "circleci token",
			id:     "circleci",
			values: map[string]string{"token": "abc123"},
			want:   []string{"circleci", "--token=abc123"},
		},
		{
			name:   "gitlab token",
			id:     "gitlab",
			values: map[string]string{"token": "glpat-xxx"},
			want:   []string{"gitlab", "--token=glpat-xxx"},
		},
		{
			name:   "gcs appends cloud-environment",
			id:     "gcs",
			values: map[string]string{"project-id": "truffle-testing"},
			want:   []string{"gcs", "--project-id=truffle-testing", "--cloud-environment"},
		},
		{
			name:   "docker splits images",
			id:     "docker",
			values: map[string]string{"image": "trufflesecurity/secrets trufflesecurity/other"},
			want:   []string{"docker", "--image=trufflesecurity/secrets", "--image=trufflesecurity/other"},
		},
		{
			name:   "s3 splits buckets",
			id:     "s3",
			values: map[string]string{"bucket": "a b c"},
			want:   []string{"s3", "--bucket=a", "--bucket=b", "--bucket=c"},
		},
		{
			name: "syslog",
			id:   "syslog",
			values: map[string]string{
				"address":  "127.0.0.1:514",
				"protocol": "tcp",
				"cert":     "/etc/cert",
				"key":      "/etc/key",
				"format":   "rfc3164",
			},
			want: []string{
				"syslog",
				"--address=127.0.0.1:514",
				"--protocol=tcp",
				"--cert=/etc/cert",
				"--key=/etc/key",
				"--format=rfc3164",
			},
		},
		{
			name:   "huggingface model only",
			id:     "huggingface",
			values: map[string]string{"model": "org/my-model"},
			want:   []string{"huggingface", "--model=org/my-model"},
		},
		{
			name: "elasticsearch local user/pass",
			id:   "elasticsearch",
			values: map[string]string{
				"username": "u",
				"password": "p",
				"nodes":    "n1 n2",
			},
			want: []string{"elasticsearch", "--username=u", "--password=p", "--nodes=n1", "--nodes=n2"},
		},
		{
			name: "elasticsearch cloud",
			id:   "elasticsearch",
			values: map[string]string{
				"cloudId": "cid",
				"apiKey":  "akey",
			},
			want: []string{"elasticsearch", "--cloudId=cid", "--apiKey=akey"},
		},
		{
			name: "jenkins unauthenticated",
			id:   "jenkins",
			values: map[string]string{
				"url": "https://ci.example.com",
			},
			want: []string{"jenkins", "--url=https://ci.example.com"},
		},
		{
			name: "jenkins authenticated",
			id:   "jenkins",
			values: map[string]string{
				"url":      "https://ci.example.com",
				"username": "u",
				"password": "p",
			},
			want: []string{"jenkins", "--url=https://ci.example.com", "--username=u", "--password=p"},
		},
		{
			name: "jenkins half-auth drops credentials",
			id:   "jenkins",
			values: map[string]string{
				"url":      "https://ci.example.com",
				"username": "u",
			},
			want: []string{"jenkins", "--url=https://ci.example.com"},
		},
		{
			name: "postman token + first non-empty target",
			id:   "postman",
			values: map[string]string{
				"token":       "PMAK-foo",
				"workspace":   "",
				"collection":  "col-1",
				"environment": "env-1",
			},
			want: []string{"postman", "--token=PMAK-foo", "--collection=col-1"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			def, ok := sources.Get(tc.id)
			if !ok {
				t.Fatalf("source %q not registered", tc.id)
			}
			adapter := sources.NewFormAdapter(def)
			for k, v := range tc.values {
				for _, f := range adapter.Form().Fields() {
					if f.Spec().Key == k {
						f.SetValue(v)
					}
				}
			}
			got := adapter.Cmd()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("args mismatch\nwant: %#v\ngot:  %#v", tc.want, got)
			}
		})
	}
}
