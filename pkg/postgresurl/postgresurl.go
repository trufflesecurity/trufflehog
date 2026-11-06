package postgresurl

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type paramsMap = map[string]string

var escaper = strings.NewReplacer(`'`, `\'`, `\`, `\\`)

// Parse accepts a string postgres url and returns libpq-style key-value pairs.
// The ParseURL function from lib/pq has been deprecated and the inner function
// is private, so this is a replacement.  We never used the single kvs string
// result of ParseURL, instead loading it into a map, so this function returns
// a map.
func Parse(str string) (paramsMap, error) {
	u, err := url.Parse(str)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("invalid connection protocol: %s", u.Scheme)
	}

	params := make(paramsMap)

	if u.User != nil {
		params["user"] = u.User.Username()

		if pw, ok := u.User.Password(); ok {
			params["password"] = pw
		}
	}

	if host := u.Hostname(); host != "" {
		params["host"] = host
	}

	if port := u.Port(); port != "" {
		params["port"] = port
	}

	if u.Path != "" {
		params["dbname"] = u.Path[1:]
	}

	q := u.Query()
	for k := range q {
		if v := q.Get(k); v != "" {
			params[k] = v
		}
	}

	return params, nil
}

// ParamsToConnStr converts a map of postgres connection parameters into a
// libpq-style connection string.
func ParamsToConnStr(params paramsMap) string {
	kvs := make([]string, 0, len(params))
	for k, v := range params {
		kvs = append(kvs, k+"='"+escaper.Replace(v)+"'")
	}
	sort.Strings(kvs)
	return strings.Join(kvs, " ")
}
