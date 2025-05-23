package engine

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/postman"
)

// ScanConfig starts a scan of all of the configured (but not initialized)
// sources and returns their job references. If there is an error during
// initialization or starting of the scan, an error is returned along with the
// references that successfully started up to that point.
func (e *Engine) ScanConfig(ctx context.Context, configuredSources ...sources.ConfiguredSource) ([]sources.JobProgressRef, error) {
	var refs []sources.JobProgressRef
	for _, configuredSource := range configuredSources {
		sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, configuredSource.Name, configuredSource.SourceType())

		source, err := configuredSource.Init(ctx, sourceID, jobID)
		if err != nil {
			return refs, err
		}
		// Postman needs special initialization to set Keywords from
		// the engine.
		if postmanSource, ok := source.(*postman.Source); ok {
			postmanSource.DetectorKeywords = e.AhoCorasickCoreKeywords()
		}

		// Start the scan.
		ref, err := e.sourceManager.EnumerateAndScan(ctx, configuredSource.Name, source)
		if err != nil {
			return refs, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
