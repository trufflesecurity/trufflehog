package handlers

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// makeAPKZip builds an in-memory zip that satisfies isAPKFile (contains both
// AndroidManifest.xml and classes.dex). A large stored padding entry is written
// first so the manifest/dex local headers fall outside mimetype's detection
// window, keeping mimetype's verdict "application/zip" rather than APK. This
// forces the content-based isAPKFile deep scan (rather than mimetype's own APK
// detection) to be what promotes the file to the APK handler.
func makeAPKZip(t *testing.T, extraFiles map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	padding, err := zw.CreateHeader(&zip.FileHeader{Name: "padding.txt", Method: zip.Store})
	require.NoError(t, err)
	_, err = padding.Write(bytes.Repeat([]byte("A"), 5000))
	require.NoError(t, err)

	for _, name := range []string{"AndroidManifest.xml", "classes.dex"} {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte("placeholder"))
		require.NoError(t, err)
	}

	for name, content := range extraFiles {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(content)
		require.NoError(t, err)
	}

	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// makeNonAPKZip builds a plain in-memory zip without any APK markers.
func makeNonAPKZip(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("hello.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("just some content"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// TestNewFileReaderAPKContentDetection verifies APK detection is driven by file
// content (the presence of AndroidManifest.xml + classes.dex) and not by any
// filename/extension: the reader is promoted to the APK mime type with no
// extension supplied, while a zip lacking those markers stays a generic zip.
func TestNewFileReaderAPKContentDetection(t *testing.T) {
	feature.EnableAPKHandler.Store(true)
	t.Cleanup(func() { feature.EnableAPKHandler.Store(false) })

	ctx := context.Background()

	rdr, err := newFileReader(ctx, bytes.NewReader(makeAPKZip(t, nil)))
	require.NoError(t, err)
	assert.Equal(t, string(apkMime), rdr.mime.String(), "APK content should route to the APK handler without an extension")
	require.NoError(t, rdr.Close())

	rdrPlain, err := newFileReader(ctx, bytes.NewReader(makeNonAPKZip(t)))
	require.NoError(t, err)
	assert.Equal(t, string(zipMime), rdrPlain.mime.String(), "a zip without APK markers should remain a generic zip")
	require.NoError(t, rdrPlain.Close())
}

// TestNewFileReaderAPKDetectionDisabled ensures APK content detection does not
// run when the feature flag is off, leaving the file as a generic zip.
func TestNewFileReaderAPKDetectionDisabled(t *testing.T) {
	feature.EnableAPKHandler.Store(false)

	rdr, err := newFileReader(context.Background(), bytes.NewReader(makeAPKZip(t, nil)))
	require.NoError(t, err)
	assert.Equal(t, string(zipMime), rdr.mime.String())
	require.NoError(t, rdr.Close())
}

// TestNewFileReaderAPKCheckErrorFallsThrough ensures that when the APK feature
// flag is on and mimetype identifies a file as a zip, but the content-based APK
// check fails to parse it (e.g. truncated/corrupted zip, or a polyglot that
// mimetype still reports as zip), newFileReader does NOT return a fatal error.
// Instead it must fall through to normal handling so the file is still processed
// rather than skipped entirely. This guards the regression where dropping the
// .apk extension guard made every unparseable zip/jar unprocessable.
func TestNewFileReaderAPKCheckErrorFallsThrough(t *testing.T) {
	feature.EnableAPKHandler.Store(true)
	t.Cleanup(func() { feature.EnableAPKHandler.Store(false) })

	// Start from a valid zip (so mimetype detects "application/zip") then truncate
	// the tail, removing the end-of-central-directory record so zip.NewReader fails.
	valid := makeNonAPKZip(t)
	truncated := valid[:len(valid)-10]

	rdr, err := newFileReader(context.Background(), bytes.NewReader(truncated))
	require.NoError(t, err, "APK check failure must not be fatal; file should fall through to normal handling")
	assert.Equal(t, string(zipMime), rdr.mime.String(), "file should remain a generic zip, not be skipped")
	require.NoError(t, rdr.Close())
}
