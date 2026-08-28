package jenkins

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceUnitKindJob sources.SourceUnitKind = "job"

// jobPathSegment is the path segment Jenkins puts before every job or folder
// name in a job URL, e.g. /job/folder1/job/build.
const jobPathSegment = "job"

// JenkinsJob is a job as listed by the Jenkins API, and is the source unit the
// Jenkins source enumerates.
type JenkinsJob struct {
	Class string `json:"_class"`
	Name  string `json:"name"`
	Url   string `json:"url"`
	// Path is the job's path relative to the Jenkins instance. Jenkins reports
	// absolute job URLs whose host comes from the instance's own root URL
	// setting, which can differ from the endpoint being scanned, so only the
	// path is retained as the identity. Chunks does the same when it scans a
	// job. Path is not part of the Jenkins API response; walkJobs derives it
	// from Url, so it is empty on a value decoded straight from a listing.
	Path string `json:"path"`
}

var _ sources.SourceUnit = JenkinsJob{}

func (j JenkinsJob) SourceUnitID() (string, sources.SourceUnitKind) {
	return j.Path, SourceUnitKindJob
}

// Display returns the job's folder path without the "job" segments Jenkins
// interleaves, e.g. /jenkins/job/folder1/job/build becomes folder1/build. It is
// derived from Path rather than from Name so that a unit rebuilt from its ID
// alone still renders a name.
func (j JenkinsJob) Display() string {
	segments := strings.Split(strings.Trim(j.Path, "/"), "/")

	// Walk in pairs so that a job named "job" and any instance base path
	// (/jenkins/) are both handled: a name is only ever the segment directly
	// after a "job" segment.
	names := make([]string, 0, len(segments)/2)
	for i := 0; i < len(segments)-1; i++ {
		if segments[i] == jobPathSegment {
			names = append(names, segments[i+1])
			i++
		}
	}

	if len(names) == 0 {
		return j.Path
	}
	return strings.Join(names, "/")
}

// unitEnvelope is the JSON shape a host application persists for an
// enumerated unit between an enumerate pass and a later scan pass: the
// SourceUnit proto marshalled with encoding/json, where unit_data carries the
// original unit as base64-encoded bytes.
type unitEnvelope struct {
	ID       string `json:"id"`
	Kind     string `json:"kind,omitempty"`
	Display  string `json:"display,omitempty"`
	UnitData string `json:"unit_data,omitempty"`
}
