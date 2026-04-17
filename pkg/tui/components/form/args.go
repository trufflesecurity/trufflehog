package form

import "strings"

// BuildArgs renders a slice of FieldSpec + values into a kingpin-style arg
// vector. It is pure (no widget state) so it can be — and is — unit tested on
// its own.
//
// Values are keyed by FieldSpec.Key. A missing or empty value emits nothing
// unless the field's EmitMode specifies otherwise.
func BuildArgs(specs []FieldSpec, values map[string]string) []string {
	var out []string
	for _, s := range specs {
		v := values[s.Key]
		if s.Transform != nil {
			v = s.Transform(strings.TrimSpace(v))
		}
		switch s.Emit {
		case EmitLongFlag:
			if strings.TrimSpace(v) == "" {
				continue
			}
			out = append(out, "--"+s.Key, v)
		case EmitLongFlagEq:
			if strings.TrimSpace(v) == "" {
				continue
			}
			out = append(out, "--"+s.Key+"="+v)
		case EmitRepeatedLongFlagEq:
			for _, piece := range strings.Fields(v) {
				out = append(out, "--"+s.Key+"="+piece)
			}
		case EmitPresence:
			if isTruthy(v) {
				out = append(out, "--"+s.Key)
			}
		case EmitConstant:
			if isTruthy(v) {
				out = append(out, s.Constant...)
			}
		case EmitPositional:
			if strings.TrimSpace(v) == "" {
				continue
			}
			out = append(out, v)
		case EmitNone:
			// no-op
		}
	}
	return out
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}
