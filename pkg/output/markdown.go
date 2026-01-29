package output

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// MarkdownPrinter renders TruffleHog findings into a Markdown document with
// dedicated tables for verified and unverified secrets. It buffers the rows
// while scanning and flushes the final report when Close is invoked.
type MarkdownPrinter struct {
	mu sync.Mutex

	out io.Writer

	verified   []markdownRow
	unverified []markdownRow

	seenVerified   map[string]struct{}
	seenUnverified map[string]struct{}
}

// markdownRow represents a single table entry in the Markdown report.
type markdownRow struct {
	Detector string
	File     string
	Line     string
	Redacted string

	lineNum int
	hasLine bool
}

func (r markdownRow) key() string {
	return fmt.Sprintf("%s|%s|%s|%s", r.Detector, r.File, r.Line, r.Redacted)
}

// NewMarkdownPrinter builds a MarkdownPrinter that writes to out. When out is
// nil, stdout is used.
func NewMarkdownPrinter(out io.Writer) *MarkdownPrinter {
	if out == nil {
		out = os.Stdout
	}
	return &MarkdownPrinter{
		out:            out,
		seenVerified:   make(map[string]struct{}),
		seenUnverified: make(map[string]struct{}),
	}
}

// Print collects each result so the final Markdown doc can include per-section
// counts and tables before the buffered results are rendered in Close.
func (p *MarkdownPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	meta, err := structToMap(r.SourceMetadata.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	file, line, lineNum, hasLine := extractFileLine(meta)

	row := markdownRow{
		Detector: sanitize(r.DetectorType.String()),
		File:     sanitize(file),
		Line:     sanitize(line),
		Redacted: sanitize(r.Redacted),
		lineNum:  lineNum,
		hasLine:  hasLine,
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	key := row.key()

	if r.Verified {
		if _, ok := p.seenVerified[key]; ok {
			return nil
		}
		p.seenVerified[key] = struct{}{}
		p.verified = append(p.verified, row)
	} else {
		if _, ok := p.seenUnverified[key]; ok {
			return nil
		}
		p.seenUnverified[key] = struct{}{}
		p.unverified = append(p.unverified, row)
	}
	return nil
}

// Close renders the buffered findings to Markdown. Close should be invoked by
// the output manager once scanning finishes.
func (p *MarkdownPrinter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	doc := renderMarkdown(p.verified, p.unverified)
	if doc == "" {
		return nil
	}
	if _, err := fmt.Fprint(p.out, doc); err != nil {
		return fmt.Errorf("write markdown: %w", err)
	}
	return nil
}

// renderMarkdown mirrors templates/trufflehog_report.py by emitting a title,
// optional sections for verified/unverified findings, and per-section counts.
func renderMarkdown(verified, unverified []markdownRow) string {
	if len(verified) == 0 && len(unverified) == 0 {
		return ""
	}

	var buf bytes.Buffer
	buf.WriteString("# TruffleHog Findings\n\n")
	writeSection := func(title string, rows []markdownRow) {
		if len(rows) == 0 {
			return
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Detector != rows[j].Detector {
				return rows[i].Detector < rows[j].Detector
			}
			if rows[i].File != rows[j].File {
				return rows[i].File < rows[j].File
			}
			if rows[i].hasLine != rows[j].hasLine {
				return rows[i].hasLine
			}
			if rows[i].lineNum != rows[j].lineNum {
				return rows[i].lineNum < rows[j].lineNum
			}
			return rows[i].Line < rows[j].Line
		})

		fmt.Fprintf(&buf, "## %s (%d)\n", title, len(rows))
		buf.WriteString("| Detector | File | Line | Redacted |\n")
		buf.WriteString("| --- | --- | --- | --- |\n")
		for _, row := range rows {
			fmt.Fprintf(&buf, "| %s | %s | %s | %s |\n", row.Detector, row.File, row.Line, row.Redacted)
		}
		buf.WriteString("\n")
	}

	writeSection("Verified Findings", verified)
	writeSection("Unverified Findings", unverified)

	return strings.TrimRight(buf.String(), "\n") + "\n"
}

var sanitizer = strings.NewReplacer("\r", " ", "\n", " ", "|", "\\|", "	", " ")

func sanitize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "n/a"
	}
	return sanitizer.Replace(value)
}


