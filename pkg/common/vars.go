package common

import (
	"path/filepath"

	"github.com/h2non/filetype"
)

var (
	KB, MB, GB, TB, PB = 1e3, 1e6, 1e9, 1e12, 1e15
	IGNORED_EXTENSIONS = []string{"pdf", "mp4", "avi", "mpeg", "mpg", "mov", "wmv", "m4p", "swf", "mp2", "flv", "vob", "webm", "hdv", "3gp", "ogg", "mp3", "wav", "flac", "tif", "tiff", "jpg", "jpeg", "png", "gif", "zip", "webp"}
)

func SkipFile(filename string, data []byte) bool {
	if filepath.Ext(filename) == "" {
		//no sepcified extension, check mimetype
		if filetype.IsArchive(data[:256]) {
			return true
		}
	}
	for _, ext := range IGNORED_EXTENSIONS {
		if filepath.Ext(filename) == ext {
			return true
		}
	}
	return false
}
