package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestParseFileOutputSpec(t *testing.T) {
	tests := []struct {
		value   string
		want    FileOutputSpec
		wantErr string
	}{
		{value: "json:results.json", want: FileOutputSpec{Format: FormatJSON, Path: "results.json"}},
		{value: "SARIF:out/results.sarif", want: FileOutputSpec{Format: FormatSARIF, Path: "out/results.sarif"}},
		{value: "json-legacy:legacy.json", want: FileOutputSpec{Format: FormatLegacyJSON, Path: "legacy.json"}},
		{value: "github-actions:annotations.txt", want: FileOutputSpec{Format: FormatGitHubActions, Path: "annotations.txt"}},
		// only the first colon separates format and path
		{value: `plain:C:\scans\results.txt`, want: FileOutputSpec{Format: FormatPlain, Path: `C:\scans\results.txt`}},
		{value: "results.json", wantErr: "expected FORMAT:PATH"},
		{value: "json:", wantErr: "expected FORMAT:PATH"},
		{value: ":results.json", wantErr: "expected FORMAT:PATH"},
		{value: "yaml:results.yaml", wantErr: `unknown format "yaml"`},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := ParseFileOutputSpec(tt.value)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

type recordingPrinter struct {
	printed int
	err     error
}

func (p *recordingPrinter) Print(context.Context, *detectors.ResultWithMetadata) error {
	p.printed++
	return p.err
}

func TestMultiPrinter_PrintsToEveryPrinterAndJoinsErrors(t *testing.T) {
	first := &recordingPrinter{err: errors.New("disk full")}
	second := &recordingPrinter{}
	third := &recordingPrinter{err: errors.New("broken pipe")}

	err := NewMultiPrinter(first, second, third).Print(context.Background(), gitResult(true))

	// a failing printer doesn't stop the ones after it
	assert.Equal(t, 1, first.printed)
	assert.Equal(t, 1, second.printed)
	assert.Equal(t, 1, third.printed)
	require.Error(t, err)
	assert.ErrorContains(t, err, "disk full")
	assert.ErrorContains(t, err, "broken pipe")
}

func TestPrintersWriteToOut(t *testing.T) {
	ctx := context.Background()

	var jsonBuf bytes.Buffer
	require.NoError(t, (&JSONPrinter{Out: &jsonBuf}).Print(ctx, gitResult(true)))
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(jsonBuf.Bytes(), &decoded))
	assert.Equal(t, "AWS", decoded["DetectorName"])

	var ghaBuf bytes.Buffer
	require.NoError(t, (&GitHubActionsPrinter{Out: &ghaBuf}).Print(ctx, gitResult(true)))
	assert.True(t, strings.HasPrefix(ghaBuf.String(), "::warning file=config/prod.yaml,line=42,endLine=42::Found verified AWS result"), ghaBuf.String())

	var plainBuf bytes.Buffer
	require.NoError(t, (&PlainPrinter{Out: &plainBuf, NoColor: true}).Print(ctx, gitResult(true)))
	assert.Contains(t, plainBuf.String(), "✅ Found verified result 🐷🔑\nDetector Type: AWS\n")
	assert.Contains(t, plainBuf.String(), "Raw result: secret\n")
	assert.NotContains(t, plainBuf.String(), "\x1b[", "NoColor output must not contain ANSI escape codes")
}

func TestGitHubActionsPrinter_DeduplicatesPerPrinter(t *testing.T) {
	ctx := context.Background()
	var first, second bytes.Buffer
	a := &GitHubActionsPrinter{Out: &first}
	b := &GitHubActionsPrinter{Out: &second}

	require.NoError(t, a.Print(ctx, gitResult(true)))
	require.NoError(t, a.Print(ctx, gitResult(true)))
	require.NoError(t, b.Print(ctx, gitResult(true)))

	assert.Equal(t, 1, strings.Count(first.String(), "::warning"), "duplicates are annotated once")
	assert.Equal(t, 1, strings.Count(second.String(), "::warning"), "another printer keeps its own dedupe state")
}

func TestOpenFileOutputs_WritesEachFormat(t *testing.T) {
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }

	// a stale file is truncated rather than appended to
	require.NoError(t, os.WriteFile(path("results.json"), []byte("stale\n"), 0o600))

	outputs, err := OpenFileOutputs([]string{
		"json:" + path("results.json"),
		"sarif:" + path("results.sarif"),
		"plain:" + path("results.txt"),
	})
	require.NoError(t, err)
	require.Len(t, outputs, 3)

	printers := make([]ResultPrinter, 0, len(outputs))
	for _, o := range outputs {
		printers = append(printers, o)
	}
	multi := NewMultiPrinter(printers...)
	ctx := context.Background()
	require.NoError(t, multi.Print(ctx, gitResult(true)))
	require.NoError(t, multi.Print(ctx, elasticsearchResult()))
	for _, o := range outputs {
		require.NoError(t, o.Close())
	}

	jsonLines := strings.Split(strings.TrimSpace(readFile(t, path("results.json"))), "\n")
	require.Len(t, jsonLines, 2)
	for _, line := range jsonLines {
		assert.True(t, json.Valid([]byte(line)), line)
	}

	var sarif sarifLog
	require.NoError(t, json.Unmarshal([]byte(readFile(t, path("results.sarif"))), &sarif))
	require.Len(t, sarif.Runs, 1)
	assert.Len(t, sarif.Runs[0].Results, 2, "SARIF is written once, on Close, with every result")

	plain := readFile(t, path("results.txt"))
	assert.Equal(t, 2, strings.Count(plain, "Found "))
	assert.NotContains(t, plain, "\x1b[")

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path("results.json"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "results contain secrets, so files are owner-only")
	}
}

func TestOpenFileOutputs_RejectsBadValues(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results.json")

	_, err := OpenFileOutputs([]string{"json:" + results, "sarif:" + results})
	require.ErrorContains(t, err, "already used by another --output")

	_, err = OpenFileOutputs([]string{"json:" + filepath.Join(dir, "missing", "results.json")})
	require.ErrorContains(t, err, "could not open output file")

	_, err = OpenFileOutputs([]string{"csv:" + results})
	require.ErrorContains(t, err, `unknown format "csv"`)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}
