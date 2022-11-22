package common

import (
	"path/filepath"
)

var (
	KB, MB, GB, TB, PB = 1e3, 1e6, 1e9, 1e12, 1e15
	IGNORED_EXTENSIONS = []string{"mp4", "avi", "mpeg", "mpg", "mov", "wmv", "m4p", "swf", "mp2", "flv", "vob", "webm", "hdv", "3gp", "ogg", "mp3", "wav", "flac", "webp"}
)

func SkipFile(filename string) bool {
	for _, ext := range IGNORED_EXTENSIONS {
		if filepath.Ext(filename) == ext {
			return true
		}
	}
	return false
}
