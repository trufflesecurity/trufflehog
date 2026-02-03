package docker

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestDockerhubListImages(t *testing.T) {
	// Dockerhub registry
	dockerhub := MakeRegistryFromNamespace("trufflesecurity") // no authentication

	dockerImages, err := dockerhub.ListImages(context.Background(), "trufflesecurity") // namespace without any prefix defaults to dockerhub registry
	assert.NoError(t, err)
	assert.Equal(t, len(dockerImages), 7)

	dockerExpectedImages := []string{
		"trufflesecurity/trufflehog", "trufflesecurity/lint-robot", "trufflesecurity/protos",
		"trufflesecurity/driftwood", "trufflesecurity/secrets", "trufflesecurity/of-cors", "trufflesecurity/email-graffiti",
	}
	slices.Sort(dockerImages)
	slices.Sort(dockerExpectedImages)
	assert.Equal(t, dockerImages, dockerExpectedImages)
}

func TestQuayListImages(t *testing.T) {
	// Quay.io registry
	quay := MakeRegistryFromNamespace("quay.io/truffledockerman") // no authentication

	quayImages, err := quay.ListImages(context.Background(), "quay.io/truffledockerman")
	assert.NoError(t, err)
	assert.Equal(t, len(quayImages), 2)

	expectedQuayImages := []string{"quay.io/truffledockerman/test", "quay.io/truffledockerman/test2"}
	slices.Sort(quayImages)
	slices.Sort(expectedQuayImages)
	assert.Equal(t, quayImages, expectedQuayImages)
}

func TestGHCRListImages(t *testing.T) {
	secret, err := common.GetTestSecret(context.Background())
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test
	githubToken := secret.MustGetField("GITHUB_PACKAGES_TEST")

	ghcr := MakeRegistryFromNamespace("ghcr.io/mongodb")
	ghcr.WithRegistryToken(githubToken) // authentication is required for GHCR

	ghcrImages, err := ghcr.ListImages(context.Background(), "ghcr.io/mongodb")
	assert.NoError(t, err)
	assert.Equal(t, len(ghcrImages), 1)

	assert.Equal(t, ghcrImages, []string{"ghcr.io/mongodb/kingfisher"})
}

func TestDockerHubListImages_RateLimitError(t *testing.T) {
	t.Parallel()

	// Dockerhub registry
	dockerhub := MakeRegistryFromNamespace("trufflesecurity") // no authentication

	// Cast dockerhub to *DockerHub registry to override the HTTP client
	dockerhub.WithClient(common.ConstantResponseHttpClient(http.StatusTooManyRequests, "{}"))
	dockerImages, err := dockerhub.ListImages(context.Background(), "trufflesecurity") // namespace without any prefix defaults to dockerhub registry
	assert.Error(t, err)
	assert.Nil(t, dockerImages)
}

func TestQuayListImages_RateLimitError(t *testing.T) {
	t.Parallel()

	// Quay.io registry
	quay := MakeRegistryFromNamespace("quay.io/truffledockerman") // no authentication
	// Cast quay to *Quay registry to override the HTTP client
	quay.WithClient(common.ConstantResponseHttpClient(http.StatusTooManyRequests, "{}"))

	quayImages, err := quay.ListImages(context.Background(), "quay.io/truffledockerman")
	assert.Error(t, err)
	assert.Nil(t, quayImages)
}

func TestGHCRListImages_RateLimitError(t *testing.T) {
	t.Parallel()

	// GHCR registry
	ghcr := MakeRegistryFromNamespace("ghcr.io/mongodb") // no authentication
	// Cast ghcr to *GHCR registry to override the HTTP client
	ghcr.WithClient(common.ConstantResponseHttpClient(http.StatusTooManyRequests, "{}"))

	ghcrImages, err := ghcr.ListImages(context.Background(), "ghcr.io/mongodb")
	assert.Error(t, err)
	assert.Nil(t, ghcrImages)
}
