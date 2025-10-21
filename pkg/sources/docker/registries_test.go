package docker

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestDockerHubListImages(t *testing.T) {
	// Dockerhub registry
	dockerhub := DockerHub{} // no authentication

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

	// Quay.io registry
	quay := Quay{} // no authentication

	quayImages, err := quay.ListImages(context.Background(), "quay.io/truffledockerman")
	assert.NoError(t, err)
	assert.Equal(t, len(quayImages), 2)

	expectedQuayImages := []string{"quay.io/truffledockerman/test", "quay.io/truffledockerman/test2"}
	slices.Sort(quayImages)
	slices.Sort(expectedQuayImages)
	assert.Equal(t, quayImages, expectedQuayImages)
}
