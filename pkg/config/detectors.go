package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	dpb "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	specialGroups = map[string][]DetectorID{
		"all": allDetectors(),
	}

	detectorTypeValue = make(map[string]dpb.DetectorType, len(dpb.DetectorType_value))
	validDetectors    = make(map[dpb.DetectorType]struct{}, len(dpb.DetectorType_value))
	maxDetectorType   dpb.DetectorType
)

// Setup package local global variables.
func init() {
	for k, v := range dpb.DetectorType_value {
		dt := dpb.DetectorType(v)
		detectorTypeValue[strings.ToLower(k)] = dt
		validDetectors[dt] = struct{}{}
		if dt > maxDetectorType {
			maxDetectorType = dt
		}
	}
}

type DetectorID struct {
	ID      dpb.DetectorType
	Version int
}

func GetDetectorID(d detectors.Detector) DetectorID {
	var version int
	if v, ok := d.(detectors.Versioner); ok {
		version = v.Version()
	}
	return DetectorID{
		ID:      d.Type(),
		Version: version,
	}
}

// ParseDetectors parses user supplied string into a list of detectors types.
// "all" will return the list of all available detectors. The input is comma
// separated and may use the case-insensitive detector name defined in the
// protobuf, or the protobuf enum number. A range may be used as well in the
// form "start-end". Order is preserved and duplicates are ignored.
func ParseDetectors(input string) ([]DetectorID, error) {
	var output []DetectorID
	seenDetector := map[DetectorID]struct{}{}
	for _, item := range strings.Split(input, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		detectors, ok := specialGroups[strings.ToLower(item)]
		if !ok {
			var err error
			detectors, err = asRange(item)
			if err != nil {
				return nil, err
			}
		}
		for _, d := range detectors {
			if _, ok := seenDetector[d]; ok {
				continue
			}
			seenDetector[d] = struct{}{}
			output = append(output, d)
		}
	}
	return output, nil
}

func (id DetectorID) String() string {
	name := dpb.DetectorType_name[int32(id.ID)]
	if name == "" {
		name = "<invalid ID>"
	}
	if id.Version == 0 {
		return name
	}
	return fmt.Sprintf("%s.v%d", name, id.Version)
}

// allDetectors reutrns an ordered slice of all detector types.
func allDetectors() []DetectorID {
	all := make([]DetectorID, 0, len(dpb.DetectorType_name))
	for id := range dpb.DetectorType_name {
		all = append(all, DetectorID{ID: dpb.DetectorType(id)})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

// asRange converts a single input into a slice of detector types. If the input
// is not in range format, a slice of length 1 is returned. Unbounded ranges
// are allowed.
func asRange(input string) ([]DetectorID, error) {
	// Check if it's a single detector type.
	dt, err := asDetectorID(input)
	if err == nil {
		return []DetectorID{dt}, nil
	}

	// Check if it's a range; if not return the error from above.
	start, end, found := strings.Cut(input, "-")
	if !found {
		return nil, err
	}
	start, end = strings.TrimSpace(start), strings.TrimSpace(end)

	// Convert the range start and end to a DetectorType.
	dtStart, err := asDetectorID(start)
	if err != nil {
		return nil, err
	}
	dtEnd, err := asDetectorID(end)
	// If end is empty it's an unbounded range.
	if err != nil && end != "" {
		return nil, err
	}
	if end == "" {
		dtEnd.ID = maxDetectorType
	}

	// Ensure these ranges don't have versions.
	if dtEnd.Version != 0 || dtStart.Version != 0 {
		return nil, fmt.Errorf("versions within ranges are not supported: %s", input)
	}

	step := dpb.DetectorType(1)
	if dtStart.ID > dtEnd.ID {
		step = -1
	}
	var output []DetectorID
	for dt := dtStart.ID; dt != dtEnd.ID; dt += step {
		if _, ok := validDetectors[dt]; !ok {
			continue
		}
		output = append(output, DetectorID{ID: dt})
	}
	return append(output, dtEnd), nil
}

// asDetectorID converts the case-insensitive input into a DetectorID.
// Name or ID may be used.
func asDetectorID(input string) (DetectorID, error) {
	if input == "" {
		return DetectorID{}, fmt.Errorf("empty detector")
	}
	var detectorID DetectorID
	// Separate the version if there is one.
	if detector, version, hasVersion := strings.Cut(input, "."); hasVersion {
		parsedVersion, err := parseVersion(version)
		if err != nil {
			return DetectorID{}, fmt.Errorf("invalid version for input: %q error: %w", input, err)
		}
		detectorID.Version = parsedVersion
		// Because there was a version, the detector type input is the part before the '.'
		input = detector
	}

	// Check if it's a named detector.
	if dt, ok := detectorTypeValue[strings.ToLower(input)]; ok {
		detectorID.ID = dt
		return detectorID, nil
	}
	// Check if it's a detector ID.
	if i, err := strconv.ParseInt(input, 10, 32); err == nil {
		dt := dpb.DetectorType(i)
		if _, ok := validDetectors[dt]; !ok {
			return DetectorID{}, fmt.Errorf("invalid detector ID: %s", input)
		}
		detectorID.ID = dt
		return detectorID, nil
	}
	return DetectorID{}, fmt.Errorf("unrecognized detector type: %s", input)
}

func parseVersion(v string) (int, error) {
	if !strings.HasPrefix(strings.ToLower(v), "v") {
		return 0, fmt.Errorf("version must start with 'v'")
	}
	version := strings.TrimLeft(v, "vV")
	return strconv.Atoi(version)
}
