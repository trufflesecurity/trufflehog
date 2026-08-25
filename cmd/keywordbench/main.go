// Command keywordbench measures what every detector's Keywords() prefilter actually
// costs on a corpus, so a new detector can be compared against the existing detector
// population before it ships.
//
// The scan reuses the engine's own chunker, decoders and Aho-Corasick core, so the
// "calls" it reports are the unverified regex passes a production scan makes over
// the same bytes. It is not the total FromData count: with verification overlap on
// (the default), the engine re-dispatches detectors that produced results for a
// second, verifying pass, which this deliberately does not model.
//
// Typical use, against the same corpus used for the regex-accuracy test:
//
//	unzstd -c contents.jsonl.zstd | jq -r .content |
//	  go run ./cmd/keywordbench -target Resend -detect -csv /tmp/kwbench
//
// Add -alt to A/B a candidate keyword set against the current one:
//
//	... | go run ./cmd/keywordbench -target Resend -detect -alt resend
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

type config struct {
	corpus      string
	target      string
	alt         string
	detect      bool
	decodeDepth int
	workers     int
	limitMB     int
	top         int
	csv         string
	dict        string
	static      bool
	verbose     bool
	progress    time.Duration
}

func main() {
	var cfg config
	flag.StringVar(&cfg.corpus, "corpus", "", "corpus file to read (default: stdin)")
	flag.StringVar(&cfg.target, "target", "", "detector name to audit in depth, e.g. Resend")
	flag.StringVar(&cfg.alt, "alt", "", "comma-separated candidate keywords to A/B against -target's current ones")
	flag.BoolVar(&cfg.detect, "detect", false, "also run FromData(verify=false) to measure regex yield and CPU cost (slower)")
	flag.IntVar(&cfg.decodeDepth, "decode-depth", 5, "iterative decode depth, matching trufflehog's --max-decode-depth. 0 disables decoding, which understates cost by roughly a third")
	flag.IntVar(&cfg.workers, "workers", runtime.NumCPU(), "concurrent scan workers")
	flag.IntVar(&cfg.limitMB, "limit-mb", 0, "stop after this many MB of corpus (0 = no limit)")
	flag.IntVar(&cfg.top, "top", 40, "rows to show in the ranked cost table")
	flag.StringVar(&cfg.csv, "csv", "", "path prefix for CSV output (writes <prefix>-detectors.csv and <prefix>-keywords.csv)")
	flag.BoolVar(&cfg.verbose, "v", false, "let detectors log; off by default because at corpus scale they flood stderr")
	flag.DurationVar(&cfg.progress, "progress", 10*time.Second, "how often to report scan progress on stderr (0 disables)")
	flag.BoolVar(&cfg.static, "static", false, "run only the corpus-free keyword lint for -target and exit")
	flag.StringVar(&cfg.dict, "dict", "/usr/share/dict/words", "word list used by the static keyword lint (skipped if absent)")
	flag.Parse()

	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "keywordbench:", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	// Detectors log their own parse failures. Over a multi-GB corpus that is tens
	// of thousands of identical lines burying the report, so mute them by default.
	if !cfg.verbose {
		context.SetDefaultLogger(logr.Discard())
	}

	enableDetectorFeatures()
	for _, w := range checkFeatureDrift("main.go") {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	all := defaults.DefaultDetectors()

	sc, err := newScanner(cfg, all)
	if err != nil {
		return err
	}

	if cfg.static {
		if sc.target == nil {
			return fmt.Errorf("-static requires -target")
		}
		renderStaticLint(os.Stdout, sc, cfg.dict)
		return nil
	}

	in := os.Stdin
	if cfg.corpus != "" {
		f, err := os.Open(cfg.corpus)
		if err != nil {
			return fmt.Errorf("opening corpus %q: %w", cfg.corpus, err)
		}
		defer f.Close()
		in = f
	}

	start := time.Now()
	tot, err := sc.scan(in)
	if err != nil {
		return fmt.Errorf("scanning corpus: %w", err)
	}
	tot.elapsed = time.Since(start)

	rep := newReport(cfg, sc, tot)
	rep.render(os.Stdout)

	if cfg.csv != "" {
		if err := rep.writeCSV(cfg.csv); err != nil {
			return fmt.Errorf("writing csv: %w", err)
		}
		fmt.Fprintf(os.Stdout, "\nwrote %s-detectors.csv and %s-keywords.csv\n", cfg.csv, cfg.csv)
	}
	return nil
}

// altDetector re-runs a real detector under a candidate keyword set so the A/B
// comparison still goes through the production span calculator. The span-sizing
// interfaces are optional and not part of detectors.Detector, so embedding the
// interface alone would silently drop them and mis-size every alt span. Resolve
// the effective values up front and re-expose all three instead.
type altDetector struct {
	detectors.Detector
	keywords  []string
	maxSecret int64
	startOff  int64
	credSpan  int64
}

func newAltDetector(d detectors.Detector, keywords []string) altDetector {
	const defaultRadius int64 = 512
	a := altDetector{
		Detector:  d,
		keywords:  keywords,
		maxSecret: defaultRadius,
		startOff:  defaultRadius,
		credSpan:  defaultRadius,
	}
	if p, ok := d.(detectors.MultiPartCredentialProvider); ok {
		a.credSpan = p.MaxCredentialSpan()
		a.maxSecret, a.startOff = a.credSpan, a.credSpan
	}
	if p, ok := d.(detectors.MaxSecretSizeProvider); ok {
		a.maxSecret = p.MaxSecretSize()
	}
	if p, ok := d.(detectors.StartOffsetProvider); ok {
		a.startOff = p.StartOffset()
	}
	return a
}

func (a altDetector) Keywords() []string       { return a.keywords }
func (a altDetector) MaxCredentialSpan() int64 { return a.credSpan }
func (a altDetector) MaxSecretSize() int64     { return a.maxSecret }
func (a altDetector) StartOffset() int64       { return a.startOff }

// displayName disambiguates the versioned detectors that share a DetectorType.
func displayName(d detectors.Detector) string {
	name := d.Type().String()
	if v, ok := d.(detectors.Versioner); ok && v.Version() > 1 {
		name = fmt.Sprintf("%s.v%d", name, v.Version())
	}
	return name
}

func detectorVersion(d detectors.Detector) int {
	if v, ok := d.(detectors.Versioner); ok {
		return v.Version()
	}
	return 0
}

// findTarget resolves a -target string against detector names, case-insensitively.
func findTarget(all []detectors.Detector, name string) (detectors.Detector, ahocorasick.DetectorKey, error) {
	var matches []detectors.Detector
	for _, d := range all {
		if strings.EqualFold(displayName(d), name) || strings.EqualFold(d.Type().String(), name) {
			matches = append(matches, d)
		}
	}
	switch len(matches) {
	case 0:
		return nil, ahocorasick.DetectorKey{}, fmt.Errorf(
			"no detector named %q among the %d enabled detectors; if it is new, check that its "+
				"feature flag is listed in cmd/keywordbench/features.go", name, len(all))
	case 1:
		return matches[0], ahocorasick.CreateDetectorKey(matches[0]), nil
	default:
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = displayName(m)
		}
		return nil, ahocorasick.DetectorKey{}, fmt.Errorf("%q is ambiguous, pick one of: %s", name, strings.Join(names, ", "))
	}
}
