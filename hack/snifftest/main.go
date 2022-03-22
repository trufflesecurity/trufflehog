package main

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paulbellamy/ratecounter"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

var (
	// CLI flags and commands
	app = kingpin.New("Snifftest", "Test secret detectors against data sets.")

	showDetectorsCmd = app.Command("show-detectors", "Shows the available detectors.")

	scanCmd           = app.Command("scan", "Scans data.")
	scanCmdDetector   = scanCmd.Flag("detector", "Detector to scan with. 'all', or a specific name.").Default("all").String()
	scanCmdExclude    = scanCmd.Flag("exclude", "Detector(s) to exclude").Strings()
	scanCmdRepo       = scanCmd.Flag("repo", "URI to .git repo.").Required().String()
	scanThreshold     = scanCmd.Flag("fail-threshold", "Result threshold that causes failure for a single scanner.").Int()
	scanPrintRes      = scanCmd.Flag("print", "Print results.").Bool()
	scanPrintChunkRes = scanCmd.Flag("print-chunk", "Print chunks that have results.").Bool()
	scanVerify        = scanCmd.Flag("verify", "Verify found secrets.").Bool()
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour*2)
	var cancelOnce sync.Once
	defer cancelOnce.Do(cancel)

	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch cmd {
	case scanCmd.FullCommand():

		chunksChan := make(chan *sources.Chunk, 10000)

		var wgChunkers sync.WaitGroup

		sem := semaphore.NewWeighted(int64(runtime.NumCPU()))

		selectedScanners := map[string]detectors.Detector{}
		allScanners := getAllScanners()

		decoders := decoders.DefaultDecoders()

		input := strings.ToLower(*scanCmdDetector)
		if input == "all" {
			selectedScanners = allScanners
		} else {
			_, ok := allScanners[input]
			if !ok {
				log.Fatal("could not find scanner by that name")
			}
			selectedScanners[input] = allScanners[input]
		}
		if len(selectedScanners) == 0 {
			log.Fatal("no detectors selected")
		}

		for _, excluded := range *scanCmdExclude {
			delete(selectedScanners, excluded)
		}

		log.Infof("loaded %d secret detectors", len(selectedScanners)+3)

		var wgScanners sync.WaitGroup

		var chunkCounter uint64
		go func() {
			counter := ratecounter.NewRateCounter(60 * time.Second)
			var prev uint64
			for {
				time.Sleep(60 * time.Second)
				counter.Incr(int64(chunkCounter - prev))
				prev = chunkCounter
				log.Infof("chunk scan rate: %d/sec", counter.Rate()/60)
			}
		}()

		resCounter := make(map[string]*uint64)
		failed := false

		for i := 0; i < runtime.NumCPU(); i++ {
			wgScanners.Add(1)

			go func() {
				defer wgScanners.Done()

				for chunk := range chunksChan {
					for name, scanner := range selectedScanners {
						for _, dec := range decoders {
							decoded := dec.FromChunk(&sources.Chunk{Data: chunk.Data})
							if decoded != nil {
								foundKeyword := false
								for _, kw := range scanner.Keywords() {
									if strings.Contains(strings.ToLower(string(decoded.Data)), strings.ToLower(kw)) {
										foundKeyword = true
									}
								}
								if !foundKeyword {
									continue
								}

								res, err := scanner.FromData(ctx, *scanVerify, decoded.Data)
								if err != nil {
									log.Fatal(err)
								}
								if len(res) > 0 {
									if resCounter[name] == nil {
										zero := uint64(0)
										resCounter[name] = &zero
									}
									atomic.AddUint64(resCounter[name], uint64(len(res)))
									if *scanThreshold != 0 && int(*resCounter[name]) > *scanThreshold {
										log.WithField("scanner", name).Errorf("exceeded result threshold of %d", *scanThreshold)
										failed = true
										os.Exit(1)
									}

									if *scanPrintRes {
										for _, r := range res {
											logger := log.WithField("secret", name).WithField("meta", chunk.SourceMetadata).WithField("result", string(r.Raw))
											if *scanPrintChunkRes {
												logger = logger.WithField("chunk", string(decoded.Data))
											}
											logger.Info("result")
										}
									}
								}
							}
						}
					}

					atomic.AddUint64(&chunkCounter, uint64(1))
				}
			}()
		}

		for _, repo := range strings.Split(*scanCmdRepo, ",") {
			sem.Acquire(ctx, 1)
			wgChunkers.Add(1)
			go func(r string) {
				defer sem.Release(1)
				defer wgChunkers.Done()
				log.Infof("cloning %s", r)
				path, repo, err := git.CloneRepoUsingUnauthenticated(r)
				if err != nil {
					log.Fatal(err)
				}

				log.Infof("cloned %s", r)

				s := git.NewGit(sourcespb.SourceType_SOURCE_TYPE_GIT, 0, 0, "snifftest", false, runtime.NumCPU(),
					func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
						return &source_metadatapb.MetaData{
							Data: &source_metadatapb.MetaData_Git{
								Git: &source_metadatapb.Git{
									Commit:     commit,
									File:       file,
									Email:      email,
									Repository: repository,
									Timestamp:  timestamp,
								},
							},
						}
					})

				log.Infof("scanning %s", r)
				err = s.ScanRepo(ctx, repo, path, git.NewScanOptions(), chunksChan)
				if err != nil {
					log.Fatal(err)
				}
				log.Infof("scanned %s", r)
				defer os.RemoveAll(path)
			}(repo)
		}

		go func() {
			wgChunkers.Wait()
			close(chunksChan)
		}()

		wgScanners.Wait()

		log.WithField("chunks", chunkCounter).Info("completed")
		for scanner, resultsCount := range resCounter {
			log.WithField("results", *resultsCount).Info(scanner)
		}

		if failed {
			os.Exit(1)
		}
	case showDetectorsCmd.FullCommand():
		for s := range getAllScanners() {
			fmt.Println(s)
		}
	}
}

func getAllScanners() map[string]detectors.Detector {
	allScanners := map[string]detectors.Detector{}
	for _, s := range engine.DefaultDetectors() {
		secretType := reflect.Indirect(reflect.ValueOf(s)).Type().PkgPath()
		path := strings.Split(secretType, "/")[len(strings.Split(secretType, "/"))-1]
		allScanners[path] = s
	}
	return allScanners
}
