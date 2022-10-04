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

func (s *sqliteJDBC) ping(ctx context.Context) bool {
	if !s.testing {
		// sqlite is not a networked database, so we cannot verify
		return false
	}
	return ping(ctx, "sqlite3", s.filename)
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
