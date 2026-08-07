package jdbc

import (
	"context"
	"errors"
	"testing"
)

func TestHostIsLocal(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Loopback and unspecified.
		{"127.0.0.1", true},
		{"127.0.0.1:5432", true},
		{"localhost", true},
		{"[::1]:1433", true},
		{"::1", true},
		{"0.0.0.0", true},
		// MySQL driver tcp(...) wrapper.
		{"tcp(127.0.0.1:3306)", true},
		{"tcp(localhost:3306)", true},
		// Private and link-local ranges.
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		// Public hosts must not be refused.
		{"db.example.com:5432", false},
		{"8.8.8.8", false},
		{"tcp(8.8.8.8:3306)", false},
		{"example.org", false},
	}

	for _, c := range cases {
		if got := hostIsLocal(c.host); got != c.want {
			t.Errorf("hostIsLocal(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestJdbcPingRefusesLocalHosts ensures every supported sub-protocol refuses to
// dial a local host during verification, matching the URI detector's existing
// local-address refusal (see issue #3679).
func TestJdbcPingRefusesLocalHosts(t *testing.T) {
	ctx := context.Background()
	pingers := map[string]jdbcPinger{
		"postgres":  &PostgresJDBC{ConnectionInfo: ConnectionInfo{Host: "127.0.0.1:5432", User: "u", Password: "p"}},
		"mysql":     &MysqlJDBC{ConnectionInfo: ConnectionInfo{Host: "tcp(localhost:3306)", User: "u", Password: "p"}},
		"sqlserver": &SqlServerJDBC{ConnectionInfo: ConnectionInfo{Host: "[::1]:1433", User: "u", Password: "p"}},
	}

	for name, p := range pingers {
		res := p.ping(ctx)
		if !res.determinate {
			t.Errorf("%s: expected determinate result for local host, got indeterminate", name)
		}
		if !errors.Is(res.err, errNoLocalIP) {
			t.Errorf("%s: expected errNoLocalIP, got %v", name, res.err)
		}
	}
}
