package filesystem

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
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

// snapshotAtChunk is a job hook that plays the part of a job monitor: when the
// stopAt-th chunk is reported it takes the job's snapshot, the only place a
// monitor can read resume info from, and then cancels the run.
type snapshotAtChunk struct {
	sources.NoopHook
	mu       sync.Mutex
	stopAt   int
	reported int
	snapshot *sources.JobProgressMetrics
}

func (h *snapshotAtChunk) ReportChunk(ref sources.JobProgressRef, _ sources.SourceUnit, _ *sources.Chunk) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reported++
	if h.reported == h.stopAt {
		snapshot := ref.Snapshot()
		h.snapshot = &snapshot
		ref.CancelRun(errors.New("stopped by the test"))
	}
}

// scanThroughManager runs a filesystem source over roots through a
// SourceManager, the way the engine does, and returns the files it scanned and
// the job's final snapshot. resumeInfo is restored into the source before the
// run, as a caller resuming a job does. A stopAt above zero interrupts the run
// at that chunk and returns the snapshot taken there instead.
func scanThroughManager(
	t *testing.T,
	roots []string,
	withUnits bool,
	resumeInfo string,
	stopAt int,
) ([]string, sources.JobProgressMetrics) {
	t.Helper()
	ctx := trContext.AddLogger(t.Context())

	conn, err := anypb.New(&sourcespb.Filesystem{Paths: roots})
	require.NoError(t, err)
	s := &Source{}
	// One worker makes the scan order the sorted order of the files.
	require.NoError(t, s.Init(ctx, "resume test", 0, 0, false, conn, 1))
	if resumeInfo != "" {
		s.GetProgress().EncodedResumeInfo = resumeInfo
	}

	hook := &snapshotAtChunk{stopAt: stopAt}
	opts := []func(*sources.SourceManager){sources.WithReportHook(hook)}
	if withUnits {
		opts = append(opts, sources.WithSourceUnits(), sources.WithConcurrentUnits(1))
	}
	mgr := sources.NewManager(opts...)

	var scanned []string
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for chunk := range mgr.Chunks() {
			scanned = append(scanned, chunk.SourceMetadata.GetFilesystem().GetFile())
		}
	}()

	ref, err := mgr.EnumerateAndScan(ctx, "resume test", s)
	require.NoError(t, err)
	<-ref.Done()
	_ = mgr.Wait()
	<-drained

	if hook.snapshot != nil {
		return scanned, *hook.snapshot
	}
	return scanned, ref.Snapshot()
}

// filesAfterResumePoint returns the files a scan restored from resumeInfo has
// left to do: within a root, the files after the root's saved path, and every
// file of a root with no saved path.
func filesAfterResumePoint(t *testing.T, filesByRoot map[string][]string, roots []string, resumeInfo string) []string {
	t.Helper()
	saved := map[string]string{}
	if resumeInfo != "" {
		require.NoError(t, json.Unmarshal([]byte(resumeInfo), &saved))
	}
	var remaining []string
	for _, root := range roots {
		files := filesByRoot[root]
		if last, ok := saved[root]; ok {
			idx := slices.Index(files, last)
			require.GreaterOrEqual(t, idx, 0, "saved path %q is not a file under %q", last, root)
			files = files[idx+1:]
		}
		remaining = append(remaining, files...)
	}
	return remaining
}

// A scan interrupted at any chunk must leave resume info in the job snapshot
// that a restarted scan can pick up from, with no file between the two runs
// left unscanned. The snapshot is the only reader of resume info here, so this
// covers the whole path from a per-root save to a restored scan.
func TestResumeInfoInSnapshotResumesScan(t *testing.T) {
	base := t.TempDir()
	filesByRoot := map[string][]string{}
	var roots, allFiles []string
	for _, rootName := range []string{"root-a", "root-b"} {
		root := filepath.Join(base, rootName)
		roots = append(roots, root)
		for _, dir := range []string{"d1", "d2/nested"} {
			require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
		}
		// In walk order: entries of a directory sorted by name, depth first.
		// No directory holds a file followed by a subdirectory, because the
		// source scans a directory's files on a worker while it walks on into
		// the subdirectories, which would leave the order to the scheduler.
		for _, name := range []string{"d1/f1", "d1/f2", "d2/nested/f3", "d2/nested/f4", "f5"} {
			path := filepath.Join(root, name)
			require.NoError(t, os.WriteFile(path, []byte("content of "+path), 0o644))
			filesByRoot[root] = append(filesByRoot[root], path)
		}
		allFiles = append(allFiles, filesByRoot[root]...)
	}

	for _, withUnits := range []bool{true, false} {
		t.Run(fmt.Sprintf("units=%t", withUnits), func(t *testing.T) {
			scanned, final := scanThroughManager(t, roots, withUnits, "", 0)
			// Units forward their chunks separately, so only the set is fixed.
			assert.ElementsMatch(t, allFiles, scanned, "an uninterrupted scan covers every file")
			if final.SourceEncodedResumeInfo != "" {
				// Every root finished, so no root has a saved path left.
				assert.JSONEq(t, `{}`, final.SourceEncodedResumeInfo)
			}

			for stopAt := 1; stopAt <= len(allFiles); stopAt++ {
				_, interrupted := scanThroughManager(t, roots, withUnits, "", stopAt)
				resumeInfo := interrupted.SourceEncodedResumeInfo

				want := filesAfterResumePoint(t, filesByRoot, roots, resumeInfo)
				if withUnits {
					// A unit hands over one chunk at a time, so when file number
					// stopAt is reported the saved path is that file or the one
					// before it in its root. A root with no saved path has either
					// not finished a file yet or has finished its last one, which
					// clears the entry.
					root := roots[(stopAt-1)/len(filesByRoot[roots[0]])]
					idx := slices.Index(filesByRoot[root], allFiles[stopAt-1])
					saved := map[string]string{}
					if resumeInfo != "" {
						require.NoError(t, json.Unmarshal([]byte(resumeInfo), &saved))
					}
					if last, ok := saved[root]; ok {
						assert.Contains(t, []int{idx - 1, idx}, slices.Index(filesByRoot[root], last),
							"stopped at chunk %d: resume info %s is not at the file being reported", stopAt, resumeInfo)
					} else {
						assert.Contains(t, []int{0, len(filesByRoot[root]) - 1}, idx,
							"stopped at chunk %d: resume info %s has no entry for %s", stopAt, resumeInfo, root)
					}
				}

				resumed, _ := scanThroughManager(t, roots, withUnits, resumeInfo, 0)
				assert.ElementsMatch(t, want, resumed, "stopped at chunk %d, resumed from %s", stopAt, resumeInfo)
			}
		})
	}
}
