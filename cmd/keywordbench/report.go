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

	// Rank yield only among detectors that found something. Including the
	// zero-result majority would put any detector with a single finding near the
	// top of the scale, which is how "13 findings in 801,942 calls" once read as
	// productive.
	var yields []float64
	for _, rw := range r.rows {
		if rw.results > 0 {
			yields = append(yields, rw.yield)
		}
	}
	slices.Sort(yields)

	for i := range r.rows {
		r.rows[i].callsPctl = percentileOf(calls, r.rows[i].callsPerMB)
		if r.rows[i].results > 0 {
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
		fmt.Fprintf(bw, "  NOTE: this run was stopped early, so the numbers below cover only the %s\n"+
			"  that was scanned. Comparisons between detectors still hold; the totals do not.\n\n",
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
		return "NEVER STARTED UP", "These keywords never matched anything in this data, so it tells us " +
			"nothing either way. Try more data, or data that actually contains this service."
	case !r.cfg.detect && t.callsPctl >= 90:
		return "EXPENSIVE", "These keywords start this detector up more often than 90% of all the " +
			"others. Run again with -detect to see whether all that work actually finds anything."
	case !r.cfg.detect && t.callsPctl >= 75:
		return "WORTH A LOOK", "This is in the most expensive quarter of all detectors. Run again " +
			"with -detect to see the other half of the story: whether those runs find anything."
	case !r.cfg.detect:
		return "LOOKS FINE", "This costs about what a normal detector costs."
	case t.callsPctl >= 90 && (t.results == 0 || t.yieldPctl <= 25):
		return "TOO BROAD", "These keywords start this detector up far more often than most, and it " +
			"threw away nearly everything it was given. That work is mostly wasted. Counting " +
			"findings will not show this, because there are barely any findings to count."
	case t.callsPctl >= 90:
		return "EXPENSIVE, BUT IT WORKS", "It starts up a lot, but it does turn that into real findings. " +
			"The cost is real, but the keywords are not the problem."
	case t.callsPctl >= 75 && t.yieldPctl <= 25:
		return "WORTH A LOOK", "It is among the most expensive detectors and among the worst at " +
			"finding things. Worth narrowing the keywords before this ships."
	default:
		return "LOOKS FINE", "Both what it costs and what it finds are in the normal range."
	}
}

func (r *report) renderVerdict(w io.Writer) {
	t := *r.target
	rank := slices.IndexFunc(r.rows, func(x row) bool { return x.key == t.key }) + 1
	verdict, why := r.verdictFor(t)

	rule(w, "=")
	fmt.Fprintf(w, "  %s  --  RESULT: %s\n", strings.ToUpper(t.name), verdict)
	rule(w, "=")
	fmt.Fprintf(w, "\n  keywords: %s\n\n", quoteAll(t.keywords))
	fmt.Fprintf(w, "  %s\n\n", wrap(why, 74, "  "))

	tb := newTable()
	tb.row("  How often it runs\t%s times per MB of data\t%s\n",
		fmtFloat(t.callsPerMB), rankPhrase(t.callsPctl, len(r.rows)))
	tb.row("  Extra text it re-reads\t%s of everything scanned\t%s of all the re-reading\n",
		pct(t.regexLoad), pct(safeDiv(float64(t.regexBytes), float64(r.totalRegex))))
	tb.row("  How often it starts up\ton %s of the text checked\t\n", pct(t.wakeRate))
	if r.cfg.detect {
		tb.row("  What it found\t%s secrets in %s runs\t%s\n",
			comma(t.results), comma(t.calls), yieldPhrase(t))
		tb.row("  CPU time it uses\t%s ms per GB of data\t\n", fmtFloat(t.msPerGB))
	} else {
		tb.row("  Times it ran\t%s\t\n", comma(t.calls))
	}
	if t.calls > 0 {
		tb.row("  Most expensive rank\t%d out of %d detectors\t\n", rank, len(r.rows))
	}
	tb.flush(w)
	if t.errs > 0 {
		fmt.Fprintf(w, "\n  note: %s runs failed with an error.\n", comma(t.errs))
	}
}

// rankPhrase truncates rather than rounds, so the claim is never stronger than
// the measurement. A percentile of 0 means nothing ranked below it, which is a tie
// rather than "less often than everything".
func rankPhrase(pctl float64, population int) string {
	switch {
	case pctl >= 50:
		return fmt.Sprintf("more often than %d%% of all %d detectors", int(pctl), population)
	case pctl == 0:
		return fmt.Sprintf("tied for the lowest of all %d detectors", population)
	default:
		return fmt.Sprintf("less often than %d%% of all %d detectors", int(100-pctl), population)
	}
}

func yieldPhrase(t row) string {
	switch {
	case t.results == 0:
		return "it found nothing at all"
	case t.yieldPctl <= 25:
		return "worse than 75% of the detectors that found anything"
	default:
		return fmt.Sprintf("about %s", fmtYield(t.yield, t.calls))
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
	var sampled uint64
	for tok, n := range r.tot.samples {
		all = append(all, sample{tok, n})
		sampled += n
	}

	// The per-keyword counters are exact; the sample map stops collecting at a cap.
	var total uint64
	for _, kw := range r.target.keywords {
		if st := r.tot.kw[strings.ToLower(kw)]; st != nil {
			total += st.hits
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].token < all[j].token
	})

	section(w, "WHAT THESE KEYWORDS ACTUALLY MATCHED IN THE DATA")
	tb := newTable()
	for i := 0; i < min(12, len(all)); i++ {
		tb.row("  %s\t%s\t%s\n", comma(all[i].n), pct(float64(all[i].n)/float64(sampled)), all[i].token)
	}
	tb.flush(w)

	if r.tot.sampleCapped {
		fmt.Fprintf(w, "\n  %s matches in total. The breakdown above covers the first %s words\n"+
			"  seen (%s matches); the rest were not counted by word, to save memory.\n",
			comma(total), comma(uint64(len(all))), comma(sampled))
		return
	}
	fmt.Fprintf(w, "\n  %s matches in total, across %s different words.\n",
		comma(total), comma(uint64(len(all))))
}

func (r *report) renderNotes(w io.Writer) {
	t := *r.target
	findings := lintKeywords(r.sc, t.keywords, r.cfg.dict)
	perKeyword := len(t.keywords) > 1

	if len(findings) == 0 && !perKeyword {
		return
	}
	section(w, "THINGS TO WATCH OUT FOR")

	if perKeyword {
		var total uint64
		for _, kw := range t.keywords {
			if st := r.tot.kw[strings.ToLower(kw)]; st != nil {
				total += st.hits
			}
		}
		tb := newTable()
		tb.row("%s\n", "  keyword\tmatches\tshare\talso starts up")
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
	section(w, fmt.Sprintf("HOW IT COMPARES -- the %d most expensive detectors on this data", r.cfg.top))

	tb := newTable()
	head := "  #\tdetector\truns per MB\textra text read\tstarts up on"
	if r.cfg.detect {
		head += "\tfound\thow often it finds"
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

	fmt.Fprintf(w, "\n  runs per MB      how many times this detector runs for every MB of data.\n")
	fmt.Fprintf(w, "  extra text read  every keyword match hands the text around it back to the\n")
	fmt.Fprintf(w, "                   detector to search again. This is how much of the data\n")
	fmt.Fprintf(w, "                   that adds up to. It can pass 100%% because the same text\n")
	fmt.Fprintf(w, "                   gets re-read once per keyword match.\n")
	fmt.Fprintf(w, "  starts up on     share of the text where a keyword matched, so the\n")
	fmt.Fprintf(w, "                   detector had to run. Counted after decoding.\n")
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

	section(w, fmt.Sprintf("THE %d BUSIEST KEYWORDS IN THIS DATA", min(r.cfg.top, len(rows))))
	tb := newTable()
	tb.row("%s\n", "  #\tkeyword\tmatches\tmatches per MB\tdetectors it starts up")
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

	section(w, "COMPARING TWO KEYWORD CHOICES")
	tb := newTable()
	tb.row("%s\n", "  keywords\truns per MB\textra text read\tstarts up on\tsecrets still found")

	recall := "not measured (needs -detect)"
	if r.cfg.detect {
		if r.tot.recallTotal == 0 && r.tot.recallErrs > 0 {
			recall = fmt.Sprintf("none of %s could be checked", comma(r.tot.recallErrs))
		} else if r.tot.recallTotal == 0 {
			recall = "no secrets in this data to check"
		} else {
			recall = fmt.Sprintf("%s of %s", comma(r.tot.recallKept), comma(r.tot.recallTotal))
			if r.tot.recallErrs > 0 {
				recall += fmt.Sprintf(" (+%s unknown)", comma(r.tot.recallErrs))
			}
		}
	}
	tb.row("  %s (current)\t%s\t%s\t%s\tbaseline\n",
		quoteAll(t.keywords), fmtFloat(t.callsPerMB), pct(t.regexLoad), pct(t.wakeRate))
	tb.row("  %s (candidate)\t%s\t%s\t%s\t%s\n",
		quoteAll(r.sc.altKeywords), fmtFloat(altCallsPerMB), pct(altLoad), pct(altWake), recall)
	tb.flush(w)
	if r.tot.recallErrs > 0 {
		fmt.Fprintf(w, "\n  %s secret(s) could not be checked because the detector errored on the\n"+
			"  new keywords' text. They are not counted either way.\n", comma(r.tot.recallErrs))
	}
	fmt.Fprintf(w, "\n")

	verdict := func(format string, args ...any) {
		fmt.Fprintf(w, "  %s\n", wrap(fmt.Sprintf(format, args...), 74, "  "))
	}
	switch {
	case r.tot.altCalls == 0 && t.calls == 0:
		verdict("Neither set of keywords matched anything here, so there is nothing to compare.")
	case r.tot.altCalls == 0:
		verdict("The new keywords never match anything here. That is cheap, but try them on data " +
			"that actually contains this service before trusting them.")
	case t.calls == 0:
		verdict("The current keywords never match here, so there is no cost to compare against.")
	case !r.cfg.detect:
		verdict("The new keywords are %s to run. Run again with -detect to check whether they "+
			"still find the same secrets.", costDelta(t.calls, r.tot.altCalls))
	case r.tot.recallTotal == 0 && r.tot.recallErrs > 0:
		verdict("The new keywords are %s, but the detector failed on every secret we tried to "+
			"check, so we cannot tell whether they would still be found.",
			costDelta(t.calls, r.tot.altCalls))
	case r.tot.recallTotal == 0:
		verdict("The new keywords are %s, but no secrets turned up here, so we cannot tell whether "+
			"they would still find them. Try data that contains this service first.",
			costDelta(t.calls, r.tot.altCalls))
	case r.tot.recallKept == r.tot.recallTotal && r.tot.altCalls*2 <= t.calls:
		verdict("The new keywords are %s and still found every secret the current ones did. "+
			"Careful though: they only work when that word sits near the secret, so this is true "+
			"of this data, not a guarantee. A keyword taken from inside the secret itself can "+
			"never miss.", costDelta(t.calls, r.tot.altCalls))
	case r.tot.recallKept == r.tot.recallTotal:
		verdict("The new keywords find everything the current ones do, but are only %s. "+
			"Probably not worth changing.", costDelta(t.calls, r.tot.altCalls))
	default:
		verdict("The new keywords are %s but miss %s of %s secrets. That is the trade-off to weigh up.",
			costDelta(t.calls, r.tot.altCalls), comma(r.tot.recallTotal-r.tot.recallKept), comma(r.tot.recallTotal))
	}
}

func (r *report) renderRunDetails(w io.Writer) {
	mode := "keyword matches only (how often detectors start up)"
	if r.cfg.detect {
		mode = "keyword matches and searching (start-ups, findings and CPU time)"
	}
	decode := fmt.Sprintf("on, %d levels deep (same as trufflehog's default)", r.cfg.decodeDepth)
	if r.cfg.decodeDepth < 1 {
		decode = "OFF -- this makes the cost look about a third lower than it really is"
	} else if r.cfg.decodeDepth != 5 {
		decode = fmt.Sprintf("on, %d levels deep (trufflehog normally uses 5)", r.cfg.decodeDepth)
	}

	section(w, "ABOUT THIS RUN")
	tb := newTable()
	partial := ""
	if r.tot.interrupted {
		partial = " -- STOPPED EARLY, this is only part of the data"
	}
	tb.row("  data scanned\t%s, split into %s chunks%s\n",
		humanBytes(r.tot.corpusBytes), comma(r.tot.chunks), partial)
	tb.row("  text searched\t%s pieces (chunks, plus each one decoded)\n", comma(r.tot.variants))
	tb.row("  bytes read\t%s (chunks overlap slightly, so this is a little higher)\n", humanBytes(r.tot.scannedBytes))
	tb.row("  compared against\t%s detectors, using %s different keywords\n",
		comma(uint64(len(r.rows))), comma(uint64(len(r.sc.kwOwners))))
	tb.row("  time taken\t%s at %s/s, using %d workers\n",
		fmtDuration(r.tot.elapsed), throughput(r.tot.corpusBytes, r.tot.elapsed), r.cfg.workers)
	tb.row("  what was measured\t%s\n", mode)
	tb.row("  decoding\t%s\n", decode)
	tb.row("  total re-reading\tall detectors together re-read %.2fx the data scanned, over %s runs\n",
		safeDiv(float64(r.totalRegex), float64(r.tot.corpusBytes)), comma(r.totalCalls))
	if r.tot.readErrs > 0 {
		tb.row("  warning\t%s chunks could not be read and were skipped\n", comma(r.tot.readErrs))
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
					f(rw.msPerGB), f(rw.callsPctl), pctlCell(rw), strconv.FormatUint(rw.errs, 10),
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

// pctlCell blanks the yield percentile for detectors that found nothing, so a zero
// cannot mean both "unranked" and "worst finder" when these CSVs are joined.
func pctlCell(rw row) string {
	if rw.results == 0 {
		return ""
	}
	return f(rw.yieldPctl)
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
