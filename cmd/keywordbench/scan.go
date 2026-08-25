package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	aho "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// detStat is what one detector cost on the corpus. calls is the number of times
// FromData would run, which is the merged-span count, not the chunk count.
type detStat struct {
	variantsHit uint64
	calls       uint64
	regexBytes  uint64
	results     uint64
	nanos       uint64
	errs        uint64
}

// kwStat attributes hits to an individual keyword, so a multi-keyword detector
// shows which one is doing the damage.
type kwStat struct {
	hits        uint64
	variantsHit uint64
}

type totals struct {
	det map[ahocorasick.DetectorKey]*detStat
	kw  map[string]*kwStat
	// samples counts the identifiers the target's keywords actually landed inside,
	// which explains a loose keyword far better than any heuristic can.
	samples map[string]uint64

	// corpusBytes excludes the chunker's peek overlap and is the honest denominator
	// for per-MB rates; scannedBytes is what the prefilter actually walked.
	corpusBytes  uint64
	scannedBytes uint64
	chunks       uint64
	variants     uint64
	readErrs     uint64

	// -alt A/B figures, target detector only.
	altCalls       uint64
	altRegexBytes  uint64
	altVariantsHit uint64
	recallKept     uint64
	recallTotal    uint64

	elapsed time.Duration
	// sampleCapped records that a worker stopped collecting identifiers. The cap is
	// per worker, so the size of the merged map cannot tell you this.
	sampleCapped bool
	// interrupted marks a partial scan, so the report can say so rather than
	// presenting numbers that look like a completed run.
	interrupted bool
}

func newTotals() *totals {
	return &totals{
		det:     make(map[ahocorasick.DetectorKey]*detStat),
		kw:      make(map[string]*kwStat),
		samples: make(map[string]uint64),
	}
}

func (t *totals) detStat(k ahocorasick.DetectorKey) *detStat {
	s, ok := t.det[k]
	if !ok {
		s = new(detStat)
		t.det[k] = s
	}
	return s
}

func (t *totals) kwStat(k string) *kwStat {
	s, ok := t.kw[k]
	if !ok {
		s = new(kwStat)
		t.kw[k] = s
	}
	return s
}

func (t *totals) merge(o *totals) {
	for k, s := range o.det {
		d := t.detStat(k)
		d.variantsHit += s.variantsHit
		d.calls += s.calls
		d.regexBytes += s.regexBytes
		d.results += s.results
		d.nanos += s.nanos
		d.errs += s.errs
	}
	for k, s := range o.kw {
		d := t.kwStat(k)
		d.hits += s.hits
		d.variantsHit += s.variantsHit
	}
	for k, n := range o.samples {
		t.samples[k] += n
	}
	t.corpusBytes += o.corpusBytes
	t.scannedBytes += o.scannedBytes
	t.chunks += o.chunks
	t.variants += o.variants
	t.readErrs += o.readErrs
	t.altCalls += o.altCalls
	t.altRegexBytes += o.altRegexBytes
	t.altVariantsHit += o.altVariantsHit
	t.recallKept += o.recallKept
	t.recallTotal += o.recallTotal
	t.sampleCapped = t.sampleCapped || o.sampleCapped
}

type scanner struct {
	cfg config
	all []detectors.Detector

	core    *ahocorasick.Core
	altCore *ahocorasick.Core

	names    map[ahocorasick.DetectorKey]string
	byKey    map[ahocorasick.DetectorKey]detectors.Detector
	kwTrie   *aho.Trie
	kwOwners map[string][]string

	target      detectors.Detector
	targetKey   ahocorasick.DetectorKey
	targetKW    map[string]struct{}
	altKeywords []string
}

func newScanner(cfg config, all []detectors.Detector) (*scanner, error) {
	sc := &scanner{
		cfg:      cfg,
		all:      all,
		names:    make(map[ahocorasick.DetectorKey]string, len(all)),
		byKey:    make(map[ahocorasick.DetectorKey]detectors.Detector, len(all)),
		kwOwners: make(map[string][]string),
	}

	sc.core = ahocorasick.NewAhoCorasickCore(all)

	var kws []string
	for _, d := range all {
		key := ahocorasick.CreateDetectorKey(d)
		sc.names[key] = displayName(d)
		sc.byKey[key] = d
		for _, kw := range d.Keywords() {
			lower := strings.ToLower(kw)
			if _, seen := sc.kwOwners[lower]; !seen {
				kws = append(kws, lower)
			}
			sc.kwOwners[lower] = append(sc.kwOwners[lower], displayName(d))
		}
	}
	sc.kwTrie = aho.NewTrieBuilder().AddStrings(kws).Build()

	if cfg.target != "" {
		d, key, err := findTarget(all, cfg.target)
		if err != nil {
			return nil, err
		}
		sc.target, sc.targetKey = d, key
		sc.targetKW = make(map[string]struct{}, len(d.Keywords()))
		for _, kw := range d.Keywords() {
			sc.targetKW[strings.ToLower(kw)] = struct{}{}
		}
	}

	if cfg.alt != "" {
		if sc.target == nil {
			return nil, fmt.Errorf("-alt requires -target")
		}
		for _, k := range strings.Split(cfg.alt, ",") {
			if k = strings.TrimSpace(k); k != "" {
				sc.altKeywords = append(sc.altKeywords, k)
			}
		}
		if len(sc.altKeywords) == 0 {
			return nil, fmt.Errorf("-alt contained no keywords")
		}
		alt := newAltDetector(sc.target, sc.altKeywords)
		sc.altCore = ahocorasick.NewAhoCorasickCore([]detectors.Detector{alt})
	}

	return sc, nil
}

type job struct {
	data    []byte
	content int
}

func (sc *scanner) scan(r io.Reader) (*totals, error) {
	ctx := context.Background()
	jobs := make(chan job, sc.cfg.workers*4)

	var wg sync.WaitGroup
	results := make([]*totals, sc.cfg.workers)
	for i := range results {
		results[i] = newTotals()
		wg.Add(1)
		go func(t *totals) {
			defer wg.Done()
			newWorker(ctx, sc, t).run(jobs)
		}(results[i])
	}

	limit := uint64(sc.cfg.limitMB) * 1024 * 1024
	var read atomic.Uint64
	var readErrs uint64
	var readErr error

	stopProgress := sc.startProgress(&read, limit)

	// A full corpus pass takes hours. Stopping on Ctrl-C and reporting on what was
	// scanned is far more useful than throwing that work away, so handle the first
	// interrupt and let a second one take the default path out.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	var interrupted bool

readLoop:
	for res := range sources.NewChunkReader()(ctx, r) {
		select {
		case <-interrupt:
			signal.Stop(interrupt)
			interrupted = true
			break readLoop
		default:
		}
		if err := res.Error(); err != nil {
			readErrs++
			readErr = err
			continue
		}
		data := res.Bytes()
		if len(data) == 0 {
			continue
		}
		jobs <- job{data: data, content: res.ContentSize()}
		n := read.Add(uint64(res.ContentSize()))
		if limit > 0 && n >= limit {
			break
		}
	}
	close(jobs)
	wg.Wait()
	stopProgress()

	if readErrs > 0 && read.Load() == 0 {
		return nil, fmt.Errorf("read %d chunks, all failed, last error: %w", readErrs, readErr)
	}

	tot := newTotals()
	for _, t := range results {
		tot.merge(t)
	}
	tot.readErrs = readErrs
	tot.interrupted = interrupted
	return tot, nil
}

// startProgress reports on stderr while a long scan runs. A corpus scan can take
// hours, and without this it looks indistinguishable from a hang.
func (sc *scanner) startProgress(read *atomic.Uint64, limit uint64) (stop func()) {
	if sc.cfg.progress <= 0 {
		return func() {}
	}

	// Overwrite one line on a terminal; append lines when redirected to a file.
	tty := false
	if fi, err := os.Stderr.Stat(); err == nil {
		tty = fi.Mode()&os.ModeCharDevice != 0
	}

	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(sc.cfg.progress)
		defer ticker.Stop()
		start := time.Now()

		report := func(final bool) {
			n, elapsed := read.Load(), time.Since(start)
			line := fmt.Sprintf("  scanned %s in %s (%s/s)", humanBytes(n), fmtDuration(elapsed), throughput(n, elapsed))
			if limit > 0 {
				line += fmt.Sprintf(", %.0f%% of limit", 100*float64(n)/float64(limit))
			}
			switch {
			case final && tty:
				fmt.Fprintf(os.Stderr, "\r\033[K%s\n", line)
			case tty:
				fmt.Fprintf(os.Stderr, "\r\033[K%s", line)
			default:
				fmt.Fprintln(os.Stderr, line)
			}
		}

		for {
			select {
			case <-done:
				report(true)
				return
			case <-ticker.C:
				report(false)
			}
		}
	}()

	return func() { close(done); <-stopped }
}

type worker struct {
	ctx      context.Context
	sc       *scanner
	tot      *totals
	decoders []decoders.Decoder
	seenKW   map[string]struct{}
	variants [][]byte
}

func newWorker(ctx context.Context, sc *scanner, t *totals) *worker {
	return &worker{
		ctx:      ctx,
		sc:       sc,
		tot:      t,
		decoders: decoders.DefaultDecoders(),
		seenKW:   make(map[string]struct{}, 64),
	}
}

func (w *worker) run(jobs <-chan job) {
	for j := range jobs {
		w.tot.chunks++
		w.tot.corpusBytes += uint64(j.content)
		w.tot.scannedBytes += uint64(len(j.data))

		w.variants = w.decodeVariants(j.data, w.variants[:0])
		for _, v := range w.variants {
			w.processVariant(v)
		}
	}
}

// decodeVariants mirrors the engine's iterativeDecode (pkg/engine/engine.go) so the
// number of prefilter passes per chunk matches a real scan. That function is
// unexported, so this is a deliberate copy rather than a call; keep it in sync.
func (w *worker) decodeVariants(data []byte, out [][]byte) [][]byte {
	if w.sc.cfg.decodeDepth < 1 {
		return append(out, data)
	}

	chunk := &sources.Chunk{Data: data, OriginalData: data}
	current := [][]byte{data}
	var seen [][]byte

	for depth := 0; depth < w.sc.cfg.decodeDepth; depth++ {
		var next [][]byte
		for _, d := range current {
			for _, dec := range w.decoders {
				if depth > 0 && dec.Type() == detectorspb.DecoderType_PLAIN {
					continue
				}
				c := *chunk
				c.Data = d
				decoded := dec.FromChunk(&c)
				if decoded == nil {
					continue
				}
				out = append(out, decoded.Data)

				if depth+1 < w.sc.cfg.decodeDepth &&
					dec.Type() != detectorspb.DecoderType_PLAIN &&
					!bytes.Equal(decoded.Data, d) &&
					!slices.ContainsFunc(seen, func(s []byte) bool { return bytes.Equal(s, decoded.Data) }) {

					seen = append(seen, decoded.Data)
					next = append(next, decoded.Data)
				}
			}
		}
		if len(next) == 0 {
			break
		}
		current = next
	}
	return out
}

func (w *worker) processVariant(data []byte) {
	t := w.tot
	t.variants++

	var targetRaw map[string]struct{}

	for _, dm := range w.sc.core.FindDetectorMatches(data) {
		st := t.detStat(dm.Key)
		st.variantsHit++
		matches := dm.Matches()
		for _, m := range matches {
			st.calls++
			st.regexBytes += uint64(len(m))
		}
		if !w.sc.cfg.detect {
			continue
		}

		isTarget := w.sc.target != nil && dm.Key == w.sc.targetKey
		for _, m := range matches {
			start := time.Now()
			res, err := w.fromData(dm.Detector, m)
			st.nanos += uint64(time.Since(start))
			if err != nil {
				st.errs++
				continue
			}
			st.results += uint64(len(res))
			if !isTarget || w.sc.altCore == nil {
				continue
			}
			for _, r := range res {
				raw := rawOf(r)
				if raw == "" {
					continue
				}
				if targetRaw == nil {
					targetRaw = make(map[string]struct{})
				}
				targetRaw[raw] = struct{}{}
			}
		}
	}

	if w.sc.altCore != nil {
		w.processAlt(data, targetRaw)
	}
	w.countKeywords(data)
}

// processAlt measures what the candidate keyword set would have cost, and whether
// the secrets the current keywords found would still have reached the regex.
func (w *worker) processAlt(data []byte, targetRaw map[string]struct{}) {
	t := w.tot
	var spans [][]byte
	for _, dm := range w.sc.altCore.FindDetectorMatches(data) {
		t.altVariantsHit++
		for _, m := range dm.Matches() {
			t.altCalls++
			t.altRegexBytes += uint64(len(m))
			spans = append(spans, m)
		}
	}

	if len(targetRaw) == 0 {
		return
	}

	// Byte containment would only prove the secret was in range of the regex, not
	// that the regex still returns it. Re-run the detector on the candidate's own
	// spans instead. This only runs on variants where the current keywords already
	// found something, so it costs almost nothing.
	found := make(map[string]struct{}, len(targetRaw))
	for _, span := range spans {
		res, err := w.fromData(w.sc.target, span)
		if err != nil {
			continue
		}
		for _, r := range res {
			if raw := rawOf(r); raw != "" {
				found[raw] = struct{}{}
			}
		}
	}

	for raw := range targetRaw {
		t.recallTotal++
		if _, ok := found[raw]; ok {
			t.recallKept++
		}
	}
}

func (w *worker) countKeywords(data []byte) {
	lower := bytes.ToLower(data)
	clear(w.seenKW)
	for _, m := range w.sc.kwTrie.Match(lower) {
		k := m.MatchString()
		ks := w.tot.kwStat(k)
		ks.hits++
		if _, ok := w.seenKW[k]; !ok {
			w.seenKW[k] = struct{}{}
			ks.variantsHit++
		}
		if _, ok := w.sc.targetKW[k]; ok {
			if len(w.tot.samples) < maxSamples {
				w.tot.samples[tokenAround(lower, int(m.Pos()), len(k))]++
			} else {
				w.tot.sampleCapped = true
			}
		}
	}
}

// rawOf returns the identifier a result is deduped on, preferring Raw.
func rawOf(r detectors.Result) string {
	if len(r.Raw) > 0 {
		return string(r.Raw)
	}
	return string(r.RawV2)
}

// maxSamples bounds per-worker sample memory on a multi-hour run.
const maxSamples = 50_000

// tokenAround expands a keyword hit out to the identifier containing it, so the
// report can show what the keyword is really matching rather than guessing.
func tokenAround(data []byte, pos, length int) string {
	const maxToken = 48
	start, end := pos, pos+length
	for start > 0 && isTokenByte(data[start-1]) && pos-start < maxToken {
		start--
	}
	for end < len(data) && isTokenByte(data[end]) && end-pos < maxToken {
		end++
	}
	return string(data[start:end])
}

// isTokenByte matches the characters that make up an identifier. data is already
// lowercased by the caller, so uppercase needs no case here.
func isTokenByte(b byte) bool {
	return b == '_' || b == '-' || b == '.' ||
		(b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// fromData mirrors the engine's per-call timeout and isolates detector panics, so
// one misbehaving detector cannot hang or abort a multi-hour corpus run.
func (w *worker) fromData(d detectors.Detector, data []byte) (res []detectors.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("detector %s panicked: %v", d.Type(), r)
		}
	}()
	ctx, cancel := context.WithTimeout(w.ctx, detectors.DefaultResponseTimeout)
	defer cancel()
	return d.FromData(ctx, false, data)
}
