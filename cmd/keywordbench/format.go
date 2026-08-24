package main

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// alignedTable lets every row carry the same cell count, which is what keeps
// tabwriter aligning a block, and then trims the padding an empty trailing cell
// would otherwise leave hanging off the end of the line.
type alignedTable struct {
	buf bytes.Buffer
	tw  *tabwriter.Writer
}

func newTable() *alignedTable {
	t := new(alignedTable)
	t.tw = tabwriter.NewWriter(&t.buf, 0, 0, 2, ' ', 0)
	return t
}

func (t *alignedTable) row(format string, args ...any) { fmt.Fprintf(t.tw, format, args...) }

func (t *alignedTable) flush(w io.Writer) {
	t.tw.Flush()
	for _, line := range strings.Split(strings.TrimSuffix(t.buf.String(), "\n"), "\n") {
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func comma(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTP"[exp])
}

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func throughput(n uint64, d time.Duration) string {
	if d <= 0 {
		return "n/a"
	}
	return humanBytes(uint64(float64(n) / d.Seconds()))
}

// fmtFloat keeps wide-dynamic-range columns readable: thousands stay whole, small
// rates keep enough precision to tell 0.001 from zero.
func fmtFloat(v float64) string {
	switch {
	case v == 0:
		return "0"
	case v >= 1000:
		return comma(uint64(v + 0.5))
	case v >= 10:
		return fmt.Sprintf("%.1f", v)
	case v >= 0.01:
		return fmt.Sprintf("%.3f", v)
	default:
		return fmt.Sprintf("%.2e", v)
	}
}

func pct(v float64) string {
	switch {
	case v == 0:
		return "0%"
	case v < 0.0001:
		return "<0.01%"
	case v < 0.01:
		return fmt.Sprintf("%.3f%%", v*100)
	default:
		return fmt.Sprintf("%.1f%%", v*100)
	}
}

// fmtYield renders results-per-call. Below 1% the "1 in N" form is far easier to
// reason about than a long string of zeros.
func fmtYield(yield float64, calls uint64) string {
	switch {
	case calls == 0:
		return "-"
	case yield == 0:
		return "0 (none)"
	case yield < 0.01:
		return "1 in " + comma(uint64(1/yield))
	default:
		return fmt.Sprintf("%.3f", yield)
	}
}

// f formats for CSV, where full precision matters more than readability.
func f(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func quoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(q, " ") + "]"
}

// costDelta describes the candidate keyword set relative to the current one.
func costDelta(current, candidate uint64) string {
	switch {
	case candidate == 0:
		return "eliminates all calls"
	case current == 0:
		return "adds calls where there were none"
	case current >= candidate:
		return fmt.Sprintf("%.1fx cheaper", float64(current)/float64(candidate))
	default:
		return fmt.Sprintf("%.1fx more expensive", float64(candidate)/float64(current))
	}
}

func wrap(s string, width int, indent string) string {
	var lines []string
	var line string
	for _, word := range strings.Fields(s) {
		if line == "" {
			line = word
			continue
		}
		if len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = word
			continue
		}
		line += " " + word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"+indent)
}
