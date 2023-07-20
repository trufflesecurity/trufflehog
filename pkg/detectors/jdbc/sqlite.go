package jdbc

import (
	"context"
	"errors"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type sqliteJDBC struct {
	filename string
	params   map[string]string
	testing  bool
}

var cannotVerifySqliteError error = errors.New("sqlite credentials cannot be verified")

func (s *sqliteJDBC) ping(ctx context.Context) pingResult {
	if !s.testing {
		// sqlite is not a networked database, so we cannot verify
		return pingResult{cannotVerifySqliteError, true}
	}
	return ping(ctx, "sqlite3", isSqliteErrorDeterminate, s.filename)
}

func isSqliteErrorDeterminate(err error) bool {
	return true
}

func parseSqlite(subname string) (jdbc, error) {
	filename, params, _ := strings.Cut(subname, "?")
	if filename == "" {
		return nil, errors.New("empty filename")
	}
	j := &sqliteJDBC{filename: filename, params: map[string]string{}}
	for _, keyVal := range strings.Split(params, "&") {
		if key, val, found := strings.Cut(keyVal, "="); found {
			j.params[key] = val
		}
	}
	return j, nil
}
