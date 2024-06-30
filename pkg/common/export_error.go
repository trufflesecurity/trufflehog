package common

// ExportError is an implementation of error that can be JSON marshalled. It
// must be a public exported type for this reason.
type ExportError string

func (e ExportError) Error() string { return string(e) }

// ExportErrors converts a list of errors into []ExportError.
func ExportErrors(errs ...error) []error {
	output := make([]error, 0, len(errs))
	for _, err := range errs {
		output = append(output, ExportError(err.Error()))
	}
	return output
}
