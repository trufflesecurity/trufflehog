package detectors

var _ MultiPartCredentialProvider = (*DefaultMultiPartCredentialProvider)(nil)
var _ MultiPartCredentialProvider = (*CustomMultiPartCredentialProvider)(nil)

type DefaultMultiPartCredentialProvider struct{}

const defaultMaxCredentialSpan = 1024

// MaxCredentialSpan returns the default maximum credential span of 1024 for the
// DefaultMultiPartCredentialProvider.
func (d DefaultMultiPartCredentialProvider) MaxCredentialSpan() int64 {
	return defaultMaxCredentialSpan
}

type CustomMultiPartCredentialProvider struct{ maxCredentialSpan int64 }

// NewCustomMultiPartCredentialProvider creates a new instance of CustomMultiPartCredentialProvider
// with the specified maximum credential span.
func NewCustomMultiPartCredentialProvider(maxCredentialSpan int64) *CustomMultiPartCredentialProvider {
	return &CustomMultiPartCredentialProvider{maxCredentialSpan: maxCredentialSpan}
}

// MaxCredentialSpan returns the custom maximum credential span specified during the
// creation of the CustomMultiPartCredentialProvider.
func (d CustomMultiPartCredentialProvider) MaxCredentialSpan() int64 {
	return d.maxCredentialSpan
}
