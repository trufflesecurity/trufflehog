package form

import (
	"fmt"
	"strconv"
	"strings"
)

// Required returns a Validate that rejects the empty string (after trim).
//
// Unlike the legacy textinputs.Required flag, this never silently substitutes
// a placeholder — the form simply refuses to submit until the user enters a
// value.
func Required() Validate {
	return func(value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("required")
		}
		return nil
	}
}

// Integer returns a Validate that accepts base-10 integers in [min, max].
// Use math.MinInt / math.MaxInt for an unbounded side.
func Integer(min, max int) Validate {
	return func(value string) error {
		v := strings.TrimSpace(value)
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("must be an integer")
		}
		if n < min || n > max {
			return fmt.Errorf("must be between %d and %d", min, max)
		}
		return nil
	}
}

// OneOf returns a Validate that accepts exactly one of the supplied strings
// (case-sensitive). Used by SelectField to reject values that aren't part of
// the option set, and also useful as a free-text "enum" check.
func OneOf(options ...string) Validate {
	return func(value string) error {
		if value == "" {
			return nil
		}
		for _, o := range options {
			if value == o {
				return nil
			}
		}
		return fmt.Errorf("must be one of: %s", strings.Join(options, ", "))
	}
}

// XOrGroup returns a Constraint that requires between min and max fields in
// the named Group to have a non-empty value. Typical use: exactly one of
// {--org, --repo} for GitHub (min=1, max=1).
//
// The returned Constraint relies on FieldSpec.Group matching group.
func XOrGroup(group string, min, max int, specs []FieldSpec) Constraint {
	keys := make([]string, 0)
	for _, s := range specs {
		if s.Group == group {
			keys = append(keys, s.Key)
		}
	}
	return func(values map[string]string) error {
		set := 0
		for _, k := range keys {
			if strings.TrimSpace(values[k]) != "" {
				set++
			}
		}
		switch {
		case set < min && min == max:
			return fmt.Errorf("exactly %d of (%s) must be set", min, strings.Join(keys, ", "))
		case set < min:
			return fmt.Errorf("at least %d of (%s) must be set", min, strings.Join(keys, ", "))
		case set > max && min == max:
			return fmt.Errorf("exactly %d of (%s) may be set", max, strings.Join(keys, ", "))
		case set > max:
			return fmt.Errorf("at most %d of (%s) may be set", max, strings.Join(keys, ", "))
		}
		return nil
	}
}
