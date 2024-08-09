package github_experimental

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"google.golang.org/protobuf/types/known/anypb"
)

func createTestSource(src *sourcespb.GitHubExperimental) (*Source, *anypb.Any) {
	s := &Source{}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}
	return s, conn
}

func TestInit(t *testing.T) {
	source, conn := createTestSource(&sourcespb.GitHubExperimental{
		Repository: "https://github.com/dustin-decker/secretsandstuff.git",
		Credential: &sourcespb.GitHubExperimental_Token{
			Token: "super secret token",
		},
		ObjectDiscovery: true,
	})

	err := source.Init(context.Background(), "test - github_experimental", 0, 1337, false, conn, 1)
	assert.Nil(t, err)
	assert.Equal(t, "super secret token", source.conn.GetToken())
}
