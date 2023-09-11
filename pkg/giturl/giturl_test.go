package giturl

import (
	"testing"

	"github.com/pkg/errors"
)

func Test_NormalizeOrgRepoURL(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		Provider provider
		Repo     string
		Out      string
		Err      error
	}{
		"github is good":             {Provider: providerGithub, Repo: "https://github.com/org/repo", Out: "https://github.com/org/repo.git", Err: nil},
		"gitlab is good":             {Provider: providerGitlab, Repo: "https://gitlab.com/org/repo", Out: "https://gitlab.com/org/repo.git", Err: nil},
		"bitbucket is good":          {Provider: providerBitbucket, Repo: "https://bitbucket.com/org/repo", Out: "https://bitbucket.com/org/repo.git", Err: nil},
		"example provider is good":   {Provider: "example", Repo: "https://example.com/org/repo", Out: "https://example.com/org/repo.git", Err: nil},
		"example provider problem":   {Provider: "example", Repo: "https://example.com/org", Out: "", Err: errors.Errorf("example repo appears to be missing the repo name. Org: %q Repo url: %q", "org", "https://example.com/org")},
		"no path":                    {Provider: providerGithub, Repo: "https://github.com", Out: "", Err: errors.Errorf("Github repo appears to be missing the path. Repo url: %q", "https://github.com")},
		"org but no repo":            {Provider: providerGithub, Repo: "https://github.com/org", Out: "", Err: errors.Errorf("Github repo appears to be missing the repo name. Org: %q Repo url: %q", "org", "https://github.com/org")},
		"org but no repo with slash": {Provider: providerGithub, Repo: "https://github.com/org/", Out: "", Err: errors.Errorf("Github repo appears to be missing the repo name. Org: %q Repo url: %q", "org", "https://github.com/org/")},
		"two slashes":                {Provider: providerGithub, Repo: "https://github.com//", Out: "", Err: errors.Errorf("Github repo appears to be missing the org name. Repo url: %q", "https://github.com//")},
		"repo with trailing slash":   {Provider: providerGithub, Repo: "https://github.com/org/repo/", Out: "", Err: errors.Errorf("Github repo contains a trailing slash. Repo url: %q", "https://github.com/org/repo/")},
		"too many url path parts":    {Provider: providerGithub, Repo: "https://github.com/org/repo/unknown/", Out: "", Err: errors.Errorf("Github repo contains a trailing slash. Repo url: %q", "https://github.com/org/repo/unknown/")},
	}

	for name, tt := range tests {
		out, err := NormalizeOrgRepoURL(tt.Provider, tt.Repo)

		switch {
		case err != nil && tt.Err != nil && (err.Error() != tt.Err.Error()):
			t.Errorf("Test %q, error does not match expected error, \n got: %v \nwant: %v", name, err.Error(), tt.Err.Error())
		case (err != nil && tt.Err == nil) || (err == nil && tt.Err != nil):
			t.Errorf("Test %q, error does not match expected error, \n got: %v \nwant: %v", name, err, tt.Err)
		}

		if out != tt.Out {
			t.Errorf("Test %q, output does not match expected out, got: %q want: %q", name, out, tt.Out)
		}
	}
}

func Test_NormalizeBitbucketRepo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		Repo string
		Out  string
		Err  error
	}{
		"good":                  {Repo: "https://bitbucket.org/org/repo", Out: "https://bitbucket.org/org/repo.git", Err: nil},
		"bitbucket needs https": {Repo: "git@bitbucket.org:org/repo.git", Out: "", Err: errors.New("Bitbucket requires https repo urls: e.g. https://bitbucket.org/org/repo.git")},
	}

	for name, tt := range tests {
		out, err := NormalizeBitbucketRepo(tt.Repo)

		switch {
		case err != nil && tt.Err != nil && (err.Error() != tt.Err.Error()):
			t.Errorf("Test %q, error does not match expected error, \n got: %v \nwant: %v", name, err.Error(), tt.Err.Error())
		case (err != nil && tt.Err == nil) || (err == nil && tt.Err != nil):
			t.Errorf("Test %q, error does not match expected error, \n got: %v \nwant: %v", name, err, tt.Err)
		}

		if out != tt.Out {
			t.Errorf("Test %q, output does not match expected out, got: %q want: %q", name, out, tt.Out)
		}
	}
}

func Test_NormalizeGitlabRepo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		Repo string
		Out  string
		Err  error
	}{
		"good":                    {Repo: "https://gitlab.com/org/repo", Out: "https://gitlab.com/org/repo.git", Err: nil},
		"gitlab needs http/https": {Repo: "git@gitlab.com:org/repo.git:", Out: "", Err: errors.New("Gitlab requires http/https repo urls: e.g. https://gitlab.com/org/repo.git")},
	}

	for name, tt := range tests {
		out, err := NormalizeGitlabRepo(tt.Repo)

		switch {
		case err != nil && tt.Err != nil && (err.Error() != tt.Err.Error()):
			t.Errorf("Test %q, error does not match expected error, \n got: %v \nwant: %v", name, err.Error(), tt.Err.Error())
		case (err != nil && tt.Err == nil) || (err == nil && tt.Err != nil):
			t.Errorf("Test %q, error does not match expected error, \n got: %v \nwant: %v", name, err, tt.Err)
		}

		if out != tt.Out {
			t.Errorf("Test %q, output does not match expected out, got: %q want: %q", name, out, tt.Out)
		}
	}
}

func TestGenerateLink(t *testing.T) {
	t.Parallel()

	type args struct {
		repo   string
		commit string
		file   string
		line   int64
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "github link gen",
			args: args{
				repo:   "https://github.com/trufflesec-julian/confluence-go-api.git",
				commit: "047b4a2ba42fc5b6c0bd535c5307434a666db5ec",
				file:   ".gitignore",
			},
			want: "https://github.com/trufflesec-julian/confluence-go-api/blob/047b4a2ba42fc5b6c0bd535c5307434a666db5ec/.gitignore",
		},
		{
			name: "github link gen with line",
			args: args{
				repo:   "https://github.com/trufflesec-julian/confluence-go-api.git",
				commit: "047b4a2ba42fc5b6c0bd535c5307434a666db5ec",
				file:   ".gitignore",
				line:   int64(4),
			},
			want: "https://github.com/trufflesec-julian/confluence-go-api/blob/047b4a2ba42fc5b6c0bd535c5307434a666db5ec/.gitignore#L4",
		},
		{
			name: "github link gen - no file",
			args: args{
				repo:   "https://github.com/trufflesec-julian/confluence-go-api.git",
				commit: "047b4a2ba42fc5b6c0bd535c5307434a666db5ec",
			},
			want: "https://github.com/trufflesec-julian/confluence-go-api/commit/047b4a2ba42fc5b6c0bd535c5307434a666db5ec",
		},
		{
			name: "Azure link gen",
			args: args{
				repo:   "https://dev.azure.com/org/project/_git/repo",
				commit: "abcdef",
				file:   "main.go",
			},
			want: "https://dev.azure.com/org/project/_git/repo/commit/abcdef/main.go",
		},
		{
			name: "Azure link gen with line",
			args: args{
				repo:   "https://dev.azure.com/org/project/_git/repo",
				commit: "abcdef",
				file:   "main.go",
				line:   int64(20),
			},
			want: "https://dev.azure.com/org/project/_git/repo/commit/abcdef/main.go?line=20",
		},
		{
			name: "Unknown provider on-prem instance",
			args: args{
				repo:   "https://onprem.customdomain.com/org/repo.git",
				commit: "xyz123",
				file:   "main.go",
				line:   int64(30),
			},
			want: "https://onprem.customdomain.com/org/repo/blob/xyz123/main.go#L30",
		},
		{
			name: "Unknown provider on-prem instance - no file",
			args: args{
				repo:   "https://onprem.customdomain.com/org/repo.git",
				commit: "xyz123",
			},
			want: "https://onprem.customdomain.com/org/repo/commit/xyz123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateLink(tt.args.repo, tt.args.commit, tt.args.file, tt.args.line); got != tt.want {
				t.Errorf("generateLink() = %v, want %v", got, tt.want)
			}
		})
	}
}
