package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// GitHubActionsPrinter is a printer that prints results in GitHub Actions format.
type GitHubActionsPrinter struct {
	mu sync.Mutex
	// Out is where results are written. Defaults to os.Stdout.
	Out io.Writer
	// seen holds the results already printed, so each file/line/detector is annotated once.
	seen map[string]struct{}
}

func (p *GitHubActionsPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	out := gitHubActionsOutputFormat{
		DetectorType:        r.DetectorType.String(),
		DetectorDescription: r.DetectorDescription,
		DecoderType:         r.DecoderType.String(),
		Verified:            r.Verified,
	}

	meta, err := structToMap(r.SourceMetadata.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	out.Filename, out.StartLine = extractFileAndLine(meta)

	verifiedStatus := "unverified"
	if out.Verified {
		verifiedStatus = "verified"
	}

	key := fmt.Sprintf("%s:%s:%s:%s:%d", out.DecoderType, out.DetectorType, verifiedStatus, out.Filename, out.StartLine)
	h := sha256.New()
	h.Write([]byte(key))
	key = hex.EncodeToString(h.Sum(nil))
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[key]; ok {
		return nil
	}
	if p.seen == nil {
		p.seen = make(map[string]struct{})
	}
	p.seen[key] = struct{}{}

	name := ""
	if nameValue, ok := r.ExtraData["name"]; ok {
		name = fmt.Sprintf(" (%s)", nameValue)
	}

	message := fmt.Sprintf("Found %s %s%s result 🐷🔑\n", verifiedStatus, out.DetectorType, name)
	if r.DecoderType != detectorspb.DecoderType_PLAIN {
		message = fmt.Sprintf("Found %s %s%s result with %s encoding 🐷🔑\n", verifiedStatus, out.DetectorType, name, out.DecoderType)
	}

	if _, err := fmt.Fprint(writerOrStdout(p.Out), formatWarningCommand(out.Filename, out.StartLine, message)); err != nil {
		return fmt.Errorf("could not write result: %w", err)
	}

	return nil
}

func formatWarningCommand(file string, line int64, message string) string {
	return fmt.Sprintf("::warning file=%s,line=%d,endLine=%d::%s\n",
		escapeWorkflowProperty(file), line, line, escapeWorkflowData(strings.TrimSuffix(message, "\n")))
}

func escapeWorkflowData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func escapeWorkflowProperty(s string) string {
	s = escapeWorkflowData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

type gitHubActionsOutputFormat struct {
	DetectorType        string
	DetectorDescription string
	DecoderType         string
	Verified            bool
	StartLine           int64
	Filename            string
}
