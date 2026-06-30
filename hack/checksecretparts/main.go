// checksecretparts is a static analysis tool that finds detector packages
// which construct detectors.Result values without populating the SecretParts
// field.
//
// It runs as WARNING by default (exit code 0 even when findings exist). Pass
// -fail to exit non-zero on findings; this is intended for use after every
// detector has been migrated to populate SecretParts (see the SecretParts
// design doc, step C).
//
// Usage:
//
//	go run ./hack/checksecretparts [dir ...]
//	go run ./hack/checksecretparts -fail ./pkg/detectors/...
//
// With no arguments, it scans ./pkg/detectors. The "/..." suffix is accepted
// for parity with go list but is stripped — the tool always recurses.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var (
		failOnFindings bool
		quiet          bool
	)
	flag.BoolVar(&failOnFindings, "fail", false, "exit 1 if any findings are reported (default: warning-only)")
	flag.BoolVar(&quiet, "quiet", false, "suppress the summary line when no findings are reported")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] [dir ...]\n", os.Args[0])
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "\nFinds detector packages that construct detectors.Result without setting SecretParts.")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "\nFlags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"./pkg/detectors"}
	}

	pkgDirs, err := collectPackageDirs(roots)
	if err != nil {
		fmt.Fprintln(os.Stderr, "checksecretparts:", err)
		os.Exit(2)
	}

	var findings []Finding
	for _, dir := range pkgDirs {
		f, err := CheckPackageDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "checksecretparts: %s: %v\n", dir, err)
			os.Exit(2)
		}
		findings = append(findings, f...)
	}

	for _, f := range findings {
		fmt.Printf("%s: warning: detectors.Result constructed without SecretParts\n", f.Position)
	}

	if len(findings) > 0 {
		pkgs := map[string]struct{}{}
		for _, f := range findings {
			pkgs[f.Package] = struct{}{}
		}
		fmt.Fprintf(os.Stderr, "checksecretparts: %d finding(s) across %d package(s) constructing detectors.Result without SecretParts\n", len(findings), len(pkgs))
		if failOnFindings {
			os.Exit(1)
		}
		return
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "checksecretparts: scanned %d package(s), no findings\n", len(pkgDirs))
	}
}

// collectPackageDirs expands the caller-supplied roots into a sorted,
// deduplicated list of directories containing at least one non-test .go file.
func collectPackageDirs(roots []string) ([]string, error) {
	seen := map[string]struct{}{}
	var dirs []string
	for _, r := range roots {
		r = strings.TrimSuffix(r, "/...")
		r = strings.TrimSuffix(r, "/")
		info, err := os.Stat(r)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", r, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", r)
		}
		err = filepath.WalkDir(r, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !d.IsDir() {
				return nil
			}
			name := d.Name()
			if path != r && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			hasGo, err := dirHasNonTestGoFile(path)
			if err != nil {
				return err
			}
			if !hasGo {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}
			seen[path] = struct{}{}
			dirs = append(dirs, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return dirs, nil
}

func dirHasNonTestGoFile(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			return true, nil
		}
	}
	return false, nil
}
