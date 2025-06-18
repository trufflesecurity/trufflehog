package azuredevopspersonalaccesstoken

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestScanner_FromData(t *testing.T) {
	scanner := Scanner{}

	// Test case with a valid key
	data := []byte("azure token: abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")
	results, err := scanner.FromData(context.Background(), false, data)
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", string(results[0].Raw))

	// Test case with no key
	data = []byte("no key here")
	results, err = scanner.FromData(context.Background(), false, data)
	assert.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestScanner_Keywords(t *testing.T) {
	scanner := Scanner{}
	keywords := scanner.Keywords()
	assert.Equal(t, []string{"azure", "token", "pat", "vsce"}, keywords)
}

func TestScanner_Type(t *testing.T) {
	scanner := Scanner{}
	assert.Equal(t, detectorspb.DetectorType_AzureDevopsPersonalAccessToken, scanner.Type())
}

func TestScanner_Description(t *testing.T) {
	scanner := Scanner{}
	assert.Equal(t, "Azure DevOps is a suite of development tools provided by Microsoft. Personal Access Tokens (PATs) are used to authenticate and authorize access to Azure DevOps services and resources.", scanner.Description())
}
