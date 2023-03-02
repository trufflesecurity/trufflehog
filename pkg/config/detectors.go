package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

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
	dt, err := asDetectorType(input)
	if err == nil {
		return []DetectorID{{ID: dt}}, nil
	}

	// Check if it's a range; if not return the error from above.
	start, end, found := strings.Cut(input, "-")
	if !found {
		return nil, err
	}
	start, end = strings.TrimSpace(start), strings.TrimSpace(end)

	// Convert the range start and end to a DetectorType.
	dtStart, err := asDetectorType(start)
	if err != nil {
		return nil, err
	}
	dtEnd, err := asDetectorType(end)
	// If end is empty it's an unbounded range.
	if err != nil && end != "" {
		return nil, err
	}
	if end == "" {
		dtEnd = maxDetectorType
	}

	step := dpb.DetectorType(1)
	if dtStart > dtEnd {
		step = -1
	}
	var output []DetectorID
	for dt := dtStart; dt != dtEnd; dt += step {
		if _, ok := validDetectors[dt]; !ok {
			continue
		}
		output = append(output, DetectorID{ID: dt})
	}
	return append(output, DetectorID{ID: dtEnd}), nil
}

// asDetectorType converts the case-insensitive input into a detector type.
// Name or ID may be used.
func asDetectorType(input string) (dpb.DetectorType, error) {
	if input == "" {
		return 0, fmt.Errorf("empty detector")
	}
	// Check if it's a named detector.
	if dt, ok := detectorTypeValue[strings.ToLower(input)]; ok {
		return dt, nil
	}
	// Check if it's a detector ID.
	if i, err := strconv.ParseInt(input, 10, 32); err == nil {
		dt := dpb.DetectorType(i)
		if _, ok := validDetectors[dt]; !ok {
			return 0, fmt.Errorf("invalid detector ID: %s", input)
		}
		return dt, nil
	}
	return 0, fmt.Errorf("unrecognized detector type: %s", input)
}
