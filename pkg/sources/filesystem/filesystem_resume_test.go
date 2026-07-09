package filesystem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// TestResumptionInChunksAfterRestart guards against a regression where a
// filesystem scan restarts from the beginning after the scanner process is
// restarted (for example by a version rollout).
//
// This exercises the legacy ENUMERATE_AND_SCAN path (Chunks), and it restores
// the resume point the same way the scanner does after reclaiming an
// in-progress job: by assigning the encoded resume info to the top-level
// Progress.EncodedResumeInfo string, WITHOUT calling SetEncodedResumeInfoFor.
//
// Both of those details matter, and are why the other resumption tests in this
// package do not catch the bug:
//
//   - They call ChunkUnit, which walks straight into scanDir. Chunks first runs
//     s.SetProgressComplete(i, len(s.paths), "...", "") for each path, and
//     SetProgressComplete unconditionally overwrites EncodedResumeInfo with its
//     (empty) fourth argument.
//   - They set the resume point via SetEncodedResumeInfoFor, which hydrates the
//     internal encodedResumeInfoByID map. Once that map is non-nil, the empty
//     SetProgressComplete write no longer matters, because GetEncodedResumeInfoFor
//     reads the map, not the string.
//
// On a freshly started process the map is still nil, so the empty write destroys
// the restored resume point before scanDir ever reads it, and the scan starts
// over from the first (lowest-sorted) entry.
func TestResumptionInChunksAfterRestart(t *testing.T) {
	ctx := trContext.Background()

	// Top-level directories that sort deterministically, mirroring the sorted
	// S3-prefix layout the customer scans.
	rootDir, err := os.MkdirTemp("", "trufflehog-resumption-chunks-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })

	dirs := []string{"aaa", "bbb", "ccc", "ddd"}
	filesByDir := make(map[string]string, len(dirs))
	for _, d := range dirs {
		dirPath := filepath.Join(rootDir, d)
		require.NoError(t, os.Mkdir(dirPath, 0755))
		filePath := filepath.Join(dirPath, "file.txt")
		require.NoError(t, os.WriteFile(filePath, []byte("content of "+d), 0644))
		filesByDir[d] = filePath
	}

	conn, err := anypb.New(&sourcespb.Filesystem{Paths: []string{rootDir}})
	require.NoError(t, err)

	s := Source{}
	// concurrency 1 keeps the walk deterministic and isolates this test from the
	// separate out-of-order resume-write behavior of scanDir's worker pool.
	require.NoError(t, s.Init(ctx, "test resumption chunks", 0, 0, true, conn, 1))

	// Simulate a job restored after already scanning through bbb/file.txt.
	// aaa and bbb must be skipped; ccc and ddd must be scanned.
	resumePoint := filesByDir["bbb"]
	encoded, err := json.Marshal(map[string]string{rootDir: resumePoint})
	require.NoError(t, err)
	s.GetProgress().EncodedResumeInfo = string(encoded)

	chunksCh := make(chan *sources.Chunk, len(dirs))
	go func() {
		defer close(chunksCh)
		assert.NoError(t, s.Chunks(ctx, chunksCh))
	}()

	scannedFiles := make(map[string]bool)
	for chunk := range chunksCh {
		scannedFiles[chunk.SourceMetadata.GetFilesystem().GetFile()] = true
	}

	assert.False(t, scannedFiles[filesByDir["aaa"]],
		"aaa/file.txt should have been skipped (before resume point); the scan restarted from the beginning")
	assert.False(t, scannedFiles[filesByDir["bbb"]],
		"bbb/file.txt should have been skipped (the resume point itself)")
	assert.True(t, scannedFiles[filesByDir["ccc"]],
		"ccc/file.txt should have been scanned (after resume point)")
	assert.True(t, scannedFiles[filesByDir["ddd"]],
		"ddd/file.txt should have been scanned (after resume point)")
}
