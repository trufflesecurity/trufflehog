package giturl

import (
	"testing"

	"github.com/pkg/errors"
)

func Test_NormalizeOrgRepoURL(t *testing.T) {
	tests := map[string]struct {
		Provider string
		Repo     string
		Out      string
		Err      error
	}{
		"github is good":             {Provider: "Github", Repo: "https://github.com/org/repo", Out: "https://github.com/org/repo.git", Err: nil},
		"gitlab is good":             {Provider: "Gitlab", Repo: "https://gitlab.com/org/repo", Out: "https://gitlab.com/org/repo.git", Err: nil},
		"bitbucket is good":          {Provider: "Bitbucket", Repo: "https://bitbucket.com/org/repo", Out: "https://bitbucket.com/org/repo.git", Err: nil},
		"example provider is good":   {Provider: "example", Repo: "https://example.com/org/repo", Out: "https://example.com/org/repo.git", Err: nil},
		"example provider problem":   {Provider: "example", Repo: "https://example.com/org", Out: "", Err: errors.Errorf("example repo appears to be missing the repo name. Org: %q Repo url: %q", "org", "https://example.com/org")},
		"no path":                    {Provider: "Github", Repo: "https://github.com", Out: "", Err: errors.Errorf("Github repo appears to be missing the path. Repo url: %q", "https://github.com")},
		"org but no repo":            {Provider: "Github", Repo: "https://github.com/org", Out: "", Err: errors.Errorf("Github repo appears to be missing the repo name. Org: %q Repo url: %q", "org", "https://github.com/org")},
		"org but no repo with slash": {Provider: "Github", Repo: "https://github.com/org/", Out: "", Err: errors.Errorf("Github repo appears to be missing the repo name. Org: %q Repo url: %q", "org", "https://github.com/org/")},
		"two slashes":                {Provider: "Github", Repo: "https://github.com//", Out: "", Err: errors.Errorf("Github repo appears to be missing the org name. Repo url: %q", "https://github.com//")},
		"repo with trailing slash":   {Provider: "Github", Repo: "https://github.com/org/repo/", Out: "", Err: errors.Errorf("Github repo contains a trailing slash. Repo url: %q", "https://github.com/org/repo/")},
		"too many url path parts":    {Provider: "Github", Repo: "https://github.com/org/repo/unknown/", Out: "", Err: errors.Errorf("Github repo contains a trailing slash. Repo url: %q", "https://github.com/org/repo/unknown/")},
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
