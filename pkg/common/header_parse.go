package common

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// ParseHeaders parses raw header entries from the --header CLI flag in
// "Name: value" form. It returns an http.Header containing all valid entries
// and a slice of per-entry errors for any that failed validation.
//
// Empty values are permitted (RFC 7230 allows empty header values); empty
// names are rejected. Names and values are validated with
// httpguts.ValidHeaderFieldName and ValidHeaderFieldValue so malformed
// headers are reported at parse time rather than silently failing every
// outbound request.
func ParseHeaders(raw []string) (http.Header, []error) {
	hdr := http.Header{}
	var errs []error
	for _, entry := range raw {
		idx := strings.Index(entry, ":")
		if idx == -1 {
			errs = append(errs, fmt.Errorf("invalid --header %q: expected 'Name: value'", entry))
			continue
		}
		key := strings.TrimSpace(entry[:idx])
		val := strings.TrimSpace(entry[idx+1:])
		if key == "" {
			errs = append(errs, fmt.Errorf("invalid --header %q: empty header name", entry))
			continue
		}
		if !httpguts.ValidHeaderFieldName(key) {
			errs = append(errs, fmt.Errorf("invalid --header %q: malformed header name %q", entry, key))
			continue
		}
		if !httpguts.ValidHeaderFieldValue(val) {
			errs = append(errs, fmt.Errorf("invalid --header %q: malformed header value", entry))
			continue
		}
		hdr.Add(key, val)
	}
	return hdr, errs
}
