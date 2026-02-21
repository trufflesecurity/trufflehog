package log

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCodeOwners(t *testing.T) {
	_, err := ParseCodeOwners(`
* @trufflesecurity/product-eng
pkg/sources/ @trufflesecurity/Scanning
pkg/writers/ @trufflesecurity/Scanning
	`)
	require.NoError(t, err)
}

func TestCodeOwners_OwnersDoNotRepeat(t *testing.T) {
	co, err := ParseCodeOwners(`
* @trufflesecurity/product-eng
pkg/sources/ @trufflesecurity/Scanning
pkg/writers/ @trufflesecurity/Scanning
	`)
	require.NoError(t, err)

	owners := co.Owners()
	require.Len(t, owners, 2)
	require.Contains(t, owners, "@trufflesecurity/product-eng")
	require.Contains(t, owners, "@trufflesecurity/Scanning")
}

func TestCodeOwners_OwnersOf(t *testing.T) {
	co, err := ParseCodeOwners(`
* @trufflesecurity/product-eng
pkg/sources/ @trufflesecurity/Scanning
pkg/writers/ @trufflesecurity/Scanning
	`)
	require.NoError(t, err)

	{
		owners, err := co.OwnersOf("github.com/trufflesecurity/trufflehog/v3/pkg/sources/filesystem.Foo")
		require.NoError(t, err)
		require.Equal(t, []string{"@trufflesecurity/Scanning"}, owners)
	}
	{
		owners, err := co.OwnersOf("main.main")
		require.NoError(t, err)
		require.Equal(t, []string{"@trufflesecurity/product-eng"}, owners)
	}
}

func TestCodeOwners_MultipleOwnersOf(t *testing.T) {
	co, err := ParseCodeOwners("* @foo @bar")
	require.NoError(t, err)

	owners, err := co.OwnersOf("main.main")
	require.NoError(t, err)
	require.Equal(t, []string{"@foo", "@bar"}, owners)
}

func TestCodeOwners_NoOwnersOf(t *testing.T) {
	co, err := ParseCodeOwners("pkg/ @foo @bar")
	require.NoError(t, err)

	owners, err := co.OwnersOf("main.main")
	require.NoError(t, err)
	require.Len(t, owners, 0)
}
