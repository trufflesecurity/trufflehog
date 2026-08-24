package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

type row struct {
	key      ahocorasick.DetectorKey
	name     string
	version  int
	keywords []string

	calls      uint64
	callsPerMB float64
	regexBytes uint64
	regexLoad  float64 // regex bytes / corpus bytes: the share of the corpus this detector re-scans
	wakeRate   float64 // variants where the prefilter woke this detector
	results    uint64
	yield      float64 // results per call
	msPerGB    float64
	errs       uint64

	callsPctl float64
	yieldPctl float64
}

type report struct {
	cfg  config
	sc   *scanner
	tot  *totals
	rows []row

	corpusMB   float64
	totalCalls uint64
	totalRegex uint64
	target     *row
}

func newReport(cfg config, sc *scanner, tot *totals) *report {
	r := &report{cfg: cfg, sc: sc, tot: tot}
	r.corpusMB = float64(tot.corpusBytes) / (1024 * 1024)

	// Every shipped detector is in the population, zero-cost ones included, so a
	// percentile reads as "worse than N% of everything we ship".
	for key, name := range sc.names {
		st := tot.det[key]
		if st == nil {
			st = new(detStat)
		}
		d := sc.byKey[key]
		rw := row{
			key:        key,
			name:       name,
			version:    detectorVersion(d),
			keywords:   d.Keywords(),
			calls:      st.calls,
			regexBytes: st.regexBytes,
			results:    st.results,
			errs:       st.errs,
		}
		if r.corpusMB > 0 {
			rw.callsPerMB = float64(st.calls) / r.corpusMB
			rw.msPerGB = (float64(st.nanos) / 1e6) / (r.corpusMB / 1024)
		}
		if tot.corpusBytes > 0 {
			rw.regexLoad = float64(st.regexBytes) / float64(tot.corpusBytes)
		}
		if tot.variants > 0 {
			rw.wakeRate = float64(st.variantsHit) / float64(tot.variants)
		}
		if st.calls > 0 {
			rw.yield = float64(st.results) / float64(st.calls)
		}
		r.rows = append(r.rows, rw)
		r.totalCalls += st.calls
		r.totalRegex += st.regexBytes
	}

	r.rankPercentiles()
	sort.Slice(r.rows, func(i, j int) bool {
		if r.rows[i].callsPerMB != r.rows[j].callsPerMB {
			return r.rows[i].callsPerMB > r.rows[j].callsPerMB
		}
		return r.rows[i].name < r.rows[j].name
	})

	if sc.target != nil {
		for i := range r.rows {
			if r.rows[i].key == sc.targetKey {
				r.target = &r.rows[i]
				break
			}
		}
	}
	return r
}

func (r *report) rankPercentiles() {
	calls := make([]float64, len(r.rows))
	for i, rw := range r.rows {
		calls[i] = rw.callsPerMB
	}
	slices.Sort(calls)

	// Yield is only defined for detectors the prefilter actually woke.
	var yields []float64
	for _, rw := range r.rows {
		if rw.calls > 0 {
			yields = append(yields, rw.yield)
		}
	}
	slices.Sort(yields)

	for i := range r.rows {
		r.rows[i].callsPctl = percentileOf(calls, r.rows[i].callsPerMB)
		if r.rows[i].calls > 0 {
			r.rows[i].yieldPctl = percentileOf(yields, r.rows[i].yield)
		}
	}
}

// percentileOf reports the share of the population strictly below v.
func percentileOf(sorted []float64, v float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	below := sort.SearchFloat64s(sorted, v)
	return 100 * float64(below) / float64(len(sorted))
}

func (r *report) render(w io.Writer) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	if r.tot.interrupted {
		fmt.Fprintf(bw, "  NOTE: interrupted. These numbers cover only the %s scanned before it\n"+
			"  stopped. Rankings are still comparable; absolute totals are not final.\n\n",
			humanBytes(r.tot.corpusBytes))
	}

	// The answer first, the evidence behind it next, the provenance last.
	if r.target != nil {
		r.renderVerdict(bw)
		r.renderSamples(bw)
		r.renderNotes(bw)
	}
	if r.sc.altCore != nil {
		r.renderAB(bw)
	}
	r.renderRanked(bw)
	if r.target == nil {
		r.renderKeywords(bw)
	}
	r.renderRunDetails(bw)
}

func rule(w io.Writer, char string) { fmt.Fprintf(w, "%s\n", strings.Repeat(char, 78)) }

func section(w io.Writer, title string) {
	fmt.Fprintf(w, "\n")
	rule(w, "-")
	fmt.Fprintf(w, "  %s\n", title)
	rule(w, "-")
}

// verdictFor turns the two numbers that matter into a call and a reason a reader
// can act on. Cost alone is judged when -detect was not used.
func (r *report) verdictFor(t row) (string, string) {
	switch {
	case t.calls == 0:
		return "UNEXERCISED", "These keywords never fired on this corpus, so it says nothing about " +
			"cost either way. Scan more data, or a corpus that contains this vendor."
	case !r.cfg.detect && t.callsPctl >= 90:
		return "HIGH COST", "These keywords fire more often than 90% of shipped detectors. " +
			"Re-run with -detect to find out whether that traffic produces any findings."
	case !r.cfg.detect && t.callsPctl >= 75:
		return "WATCH", "Cost is in the top quartile. Re-run with -detect for the other half " +
			"of the picture: whether the regex makes use of all those calls."
	case !r.cfg.detect:
		return "OK", "Prefilter cost sits in the normal range for a shipped detector."
	case t.callsPctl >= 90 && (t.results == 0 || t.yieldPctl <= 25):
		return "LOOSE", "These keywords wake the detector far more often than most, and the regex " +
			"discarded nearly everything it was handed. That is close to pure scanner overhead, " +
			"and a findings-count test cannot see it because it produces no findings to count."
	case t.callsPctl >= 90:
		return "EXPENSIVE BUT PRODUCTIVE", "A high invocation rate, but the regex converts it into " +
			"findings. The cost is real; the keywords are not the problem."
	case t.callsPctl >= 75 && t.yieldPctl <= 25:
		return "WATCH", "Cost is in the top quartile and yield in the bottom. Worth tightening " +
			"before this ships."
	default:
		return "OK", "Prefilter cost and regex yield both sit in the normal range."
	}
}

func (r *report) renderVerdict(w io.Writer) {
	t := *r.target
	rank := slices.IndexFunc(r.rows, func(x row) bool { return x.key == t.key }) + 1
	verdict, why := r.verdictFor(t)

	rule(w, "=")
	fmt.Fprintf(w, "  %s  --  VERDICT: %s\n", strings.ToUpper(t.name), verdict)
	rule(w, "=")
	fmt.Fprintf(w, "\n  keywords: %s\n\n", quoteAll(t.keywords))
	fmt.Fprintf(w, "  %s\n\n", wrap(why, 74, "  "))

	tb := newTable()
	tb.row("  How often its regex runs\t%s per MB\t%s\n",
		fmtFloat(t.callsPerMB), rankPhrase(t.callsPctl, len(r.rows)))
	tb.row("  How much corpus it re-scans\t%s\t%s of all prefilter work\n",
		pct(t.regexLoad), pct(safeDiv(float64(t.regexBytes), float64(r.totalRegex))))
	tb.row("  How often it is woken\t%s of chunks\t\n", pct(t.wakeRate))
	if r.cfg.detect {
		tb.row("  What it found\t%s secrets in %s calls\t%s\n",
			comma(t.results), comma(t.calls), yieldPhrase(t))
		tb.row("  CPU it costs\t%s ms per GB\t\n", fmtFloat(t.msPerGB))
	} else {
		tb.row("  Total calls\t%s\t\n", comma(t.calls))
	}
	tb.row("  Rank by cost\t%d of %d detectors\t\n", rank, len(r.rows))
	tb.flush(w)
	if t.errs > 0 {
		fmt.Fprintf(w, "\n  note: %s calls returned an error or panicked.\n", comma(t.errs))
	}
}

// rankPhrase truncates rather than rounds, so the claim is never stronger than
// the measurement.
func rankPhrase(pctl float64, population int) string {
	if pctl >= 50 {
		return fmt.Sprintf("more than %d%% of all %d detectors", int(pctl), population)
	}
	return fmt.Sprintf("cheaper than %d%% of all %d detectors", int(100-pctl), population)
}

func yieldPhrase(t row) string {
	switch {
	case t.results == 0:
		return "the regex used none of them"
	case t.yieldPctl <= 25:
		return "a lower hit rate than 75% of woken detectors"
	default:
		return fmt.Sprintf("%s per call", fmtYield(t.yield, t.calls))
	}
}

// renderSamples shows the identifiers the keywords actually landed inside. For a
// loose keyword this is the most direct evidence there is.
func (r *report) renderSamples(w io.Writer) {
	if len(r.tot.samples) == 0 {
		return
	}
	type sample struct {
		token string
		n     uint64
	}
	all := make([]sample, 0, len(r.tot.samples))
	var total uint64
	for tok, n := range r.tot.samples {
		all = append(all, sample{tok, n})
		total += n
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].token < all[j].token
	})

	section(w, "WHAT THESE KEYWORDS ACTUALLY MATCHED")
	tb := newTable()
	for i := 0; i < min(12, len(all)); i++ {
		tb.row("  %s\t%s\t%s\n", comma(all[i].n), pct(float64(all[i].n)/float64(total)), all[i].token)
	}
	tb.flush(w)
	capped := ""
	if len(r.tot.samples) >= maxSamples {
		capped = ", sampling capped"
	}
	fmt.Fprintf(w, "\n  %s hits across %s distinct identifiers%s.\n",
		comma(total), comma(uint64(len(all))), capped)
}

func (r *report) renderNotes(w io.Writer) {
	t := *r.target
	findings := lintKeywords(r.sc, t.keywords, r.cfg.dict)
	perKeyword := len(t.keywords) > 1

	if len(findings) == 0 && !perKeyword {
		return
	}
	section(w, "NOTES ON THESE KEYWORDS")

	if perKeyword {
		var total uint64
		for _, kw := range t.keywords {
			if st := r.tot.kw[strings.ToLower(kw)]; st != nil {
				total += st.hits
			}
		}
		tb := newTable()
		tb.row("%s\n", "  keyword\thits\tshare\talso wakes")
		for _, kw := range t.keywords {
			lower := strings.ToLower(kw)
			st := r.tot.kw[lower]
			if st == nil {
				st = new(kwStat)
			}
			shared := "-"
			if others := len(r.sc.kwOwners[lower]) - 1; others > 0 {
				shared = fmt.Sprintf("%d other detector(s)", others)
			}
			tb.row("  %q\t%s\t%s\t%s\n", kw, comma(st.hits),
				pct(safeDiv(float64(st.hits), float64(total))), shared)
		}
		tb.flush(w)
		if len(findings) > 0 {
			fmt.Fprintln(w)
		}
	}
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", wrap(f, 72, "    "))
	}
}

func (r *report) renderRanked(w io.Writer) {
	if r.cfg.top <= 0 {
		return
	}
	section(w, fmt.Sprintf("COST CONTEXT: the %d most expensive detectors on this corpus", r.cfg.top))

	tb := newTable()
	head := "  #\tdetector\tcalls/MB\tre-scans\twakes on"
	if r.cfg.detect {
		head += "\tfound\tyield"
	}
	tb.row("%s\n", head)

	shown := min(r.cfg.top, len(r.rows))
	for i := 0; i < shown; i++ {
		r.writeRow(tb, i+1, r.rows[i])
	}
	if r.target != nil && slices.IndexFunc(r.rows[:shown], func(x row) bool { return x.key == r.target.key }) < 0 {
		cells := 5
		if r.cfg.detect {
			cells = 7
		}
		gap := make([]string, cells)
		gap[1] = "..."
		tb.row("%s\n", "  "+strings.Join(gap, "\t"))
		r.writeRow(tb, slices.IndexFunc(r.rows, func(x row) bool { return x.key == r.target.key })+1, *r.target)
	}
	tb.flush(w)

	fmt.Fprintf(w, "\n  calls/MB is how many times a detector's regex runs per MB of corpus.\n")
	fmt.Fprintf(w, "  re-scans is the share of the corpus its keywords hand back to the regex;\n")
	fmt.Fprintf(w, "  it passes 100%% when the spans around separate hits overlap.\n")
}

func (r *report) writeRow(tb *alignedTable, rank int, rw row) {
	marker := " "
	if r.target != nil && rw.key == r.target.key {
		marker = ">"
	}
	line := fmt.Sprintf("%s%d\t%s\t%s\t%s\t%s",
		marker, rank, rw.name, fmtFloat(rw.callsPerMB), pct(rw.regexLoad), pct(rw.wakeRate))
	if r.cfg.detect {
		line += fmt.Sprintf("\t%s\t%s", comma(rw.results), fmtYield(rw.yield, rw.calls))
	}
	tb.row("%s\n", line)
}

func (r *report) renderKeywords(w io.Writer) {
	if r.cfg.top <= 0 {
		return
	}
	type kwRow struct {
		kw    string
		stat  *kwStat
		owner []string
	}
	var rows []kwRow
	for kw, owners := range r.sc.kwOwners {
		if st := r.tot.kw[kw]; st != nil && st.hits > 0 {
			rows = append(rows, kwRow{kw: kw, stat: st, owner: owners})
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].stat.hits > rows[j].stat.hits })

	section(w, fmt.Sprintf("THE %d BUSIEST KEYWORDS ON THIS CORPUS", min(r.cfg.top, len(rows))))
	tb := newTable()
	tb.row("%s\n", "  #\tkeyword\thits\thits/MB\tdetectors it wakes")
	for i := 0; i < min(r.cfg.top, len(rows)); i++ {
		k := rows[i]
		owners := strings.Join(k.owner, ", ")
		if len(k.owner) > 3 {
			owners = fmt.Sprintf("%s +%d more", strings.Join(k.owner[:3], ", "), len(k.owner)-3)
		}
		tb.row("  %d\t%q\t%s\t%s\t%s\n", i+1, k.kw, comma(k.stat.hits),
			fmtFloat(safeDiv(float64(k.stat.hits), r.corpusMB)), owners)
	}
	tb.flush(w)
}

func (r *report) renderAB(w io.Writer) {
	t := *r.target
	altCallsPerMB := safeDiv(float64(r.tot.altCalls), r.corpusMB)
	altLoad := safeDiv(float64(r.tot.altRegexBytes), float64(r.tot.corpusBytes))
	altWake := safeDiv(float64(r.tot.altVariantsHit), float64(r.tot.variants))

	section(w, "KEYWORD A/B")
	tb := newTable()
	tb.row("%s\n", "  keywords\tcalls/MB\tre-scans\twakes on\tstill finds")

	recall := "not measured (-detect off)"
	if r.cfg.detect {
		if r.tot.recallTotal == 0 {
			recall = "no secrets here to check"
		} else {
			recall = fmt.Sprintf("%s of %s", comma(r.tot.recallKept), comma(r.tot.recallTotal))
		}
	}
	tb.row("  %s (current)\t%s\t%s\t%s\tbaseline\n",
		quoteAll(t.keywords), fmtFloat(t.callsPerMB), pct(t.regexLoad), pct(t.wakeRate))
	tb.row("  %s (candidate)\t%s\t%s\t%s\t%s\n",
		quoteAll(r.sc.altKeywords), fmtFloat(altCallsPerMB), pct(altLoad), pct(altWake), recall)
	tb.flush(w)
	fmt.Fprintf(w, "\n")

	verdict := func(format string, args ...any) {
		fmt.Fprintf(w, "  %s\n", wrap(fmt.Sprintf(format, args...), 74, "  "))
	}
	switch {
	case r.tot.altCalls == 0 && t.calls == 0:
		verdict("Neither keyword set fired on this corpus, so there is nothing to compare.")
	case r.tot.altCalls == 0:
		verdict("The candidate never fires on this corpus. That is cheap, but check recall " +
			"on a corpus that actually contains this vendor before trusting it.")
	case t.calls == 0:
		verdict("The current keywords never fire here, so there is no cost to compare against.")
	case !r.cfg.detect:
		verdict("The candidate is %s on invocations. Re-run with -detect to measure whether "+
			"it still reaches the same secrets.", costDelta(t.calls, r.tot.altCalls))
	case r.tot.recallTotal == 0:
		verdict("The candidate is %s, but no secrets were found here, so recall is unmeasured. "+
			"Re-run on a corpus that contains this vendor before switching.", costDelta(t.calls, r.tot.altCalls))
	case r.tot.recallKept == r.tot.recallTotal && r.tot.altCalls*2 <= t.calls:
		verdict("The candidate is %s and still reaches every secret the current keywords found. "+
			"Switch to it.", costDelta(t.calls, r.tot.altCalls))
	case r.tot.recallKept == r.tot.recallTotal:
		verdict("The candidate keeps full recall but is only %s. Not worth churning for.",
			costDelta(t.calls, r.tot.altCalls))
	default:
		verdict("The candidate is %s but misses %s of %s secrets. That is the trade to decide.",
			costDelta(t.calls, r.tot.altCalls), comma(r.tot.recallTotal-r.tot.recallKept), comma(r.tot.recallTotal))
	}
}

func (r *report) renderRunDetails(w io.Writer) {
	mode := "keyword only (cost)"
	if r.cfg.detect {
		mode = "keyword + regex (cost, findings and CPU)"
	}
	decode := fmt.Sprintf("on, depth %d (matches trufflehog's default)", r.cfg.decodeDepth)
	if r.cfg.decodeDepth < 1 {
		decode = "OFF -- cost here understates production by roughly a third"
	} else if r.cfg.decodeDepth != 5 {
		decode = fmt.Sprintf("on, depth %d (trufflehog defaults to 5)", r.cfg.decodeDepth)
	}

	section(w, "RUN DETAILS")
	tb := newTable()
	partial := ""
	if r.tot.interrupted {
		partial = " (INTERRUPTED, partial)"
	}
	tb.row("  corpus\t%s in %s chunks, %s after decoding%s\n",
		humanBytes(r.tot.corpusBytes), comma(r.tot.chunks), comma(r.tot.variants), partial)
	tb.row("  prefilter saw\t%s including chunk peek overlap\n", humanBytes(r.tot.scannedBytes))
	tb.row("  population\t%s detectors, %s distinct keywords\n",
		comma(uint64(len(r.rows))), comma(uint64(len(r.sc.kwOwners))))
	tb.row("  elapsed\t%s at %s/s on %d workers\n",
		fmtDuration(r.tot.elapsed), throughput(r.tot.corpusBytes, r.tot.elapsed), r.cfg.workers)
	tb.row("  mode\t%s\n", mode)
	tb.row("  decoding\t%s\n", decode)
	tb.row("  total load\t%.2fx the corpus handed to detector regexes, across %s calls\n",
		safeDiv(float64(r.totalRegex), float64(r.tot.corpusBytes)), comma(r.totalCalls))
	if r.tot.readErrs > 0 {
		tb.row("  warning\t%s chunks failed to read and were skipped\n", comma(r.tot.readErrs))
	}
	tb.flush(w)
	fmt.Fprintf(w, "\n")
}

func (r *report) writeCSV(prefix string) error {
	if err := writeCSVFile(prefix+"-detectors.csv",
		[]string{"detector", "version", "variant", "keywords", "calls", "calls_per_mb", "regex_bytes",
			"regex_load", "wake_rate", "results", "yield", "ms_per_gb", "calls_pctl", "yield_pctl", "errors"},
		func(add func([]string)) {
			for _, rw := range r.rows {
				add([]string{
					rw.key.Type().String(), strconv.Itoa(rw.version), rw.name, strings.Join(rw.keywords, "|"),
					strconv.FormatUint(rw.calls, 10), f(rw.callsPerMB), strconv.FormatUint(rw.regexBytes, 10),
					f(rw.regexLoad), f(rw.wakeRate), strconv.FormatUint(rw.results, 10), f(rw.yield),
					f(rw.msPerGB), f(rw.callsPctl), f(rw.yieldPctl), strconv.FormatUint(rw.errs, 10),
				})
			}
		}); err != nil {
		return err
	}

	return writeCSVFile(prefix+"-keywords.csv",
		[]string{"keyword", "hits", "hits_per_mb", "variants_hit", "wake_rate", "detectors"},
		func(add func([]string)) {
			for kw, owners := range r.sc.kwOwners {
				s := r.tot.kw[kw]
				if s == nil {
					s = new(kwStat)
				}
				add([]string{kw, strconv.FormatUint(s.hits, 10), f(safeDiv(float64(s.hits), r.corpusMB)),
					strconv.FormatUint(s.variantsHit, 10),
					f(safeDiv(float64(s.variantsHit), float64(r.tot.variants))), strings.Join(owners, "|")})
			}
		})
}

func writeCSVFile(path string, header []string, rows func(add func([]string))) error {
	fh, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer fh.Close()

	cw := csv.NewWriter(fh)
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("writing header to %s: %w", path, err)
	}
	var writeErr error
	rows(func(rec []string) {
		if writeErr == nil {
			writeErr = cw.Write(rec)
		}
	})
	if writeErr != nil {
		return fmt.Errorf("writing %s: %w", path, writeErr)
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flushing %s: %w", path, err)
	}
	return nil
}
