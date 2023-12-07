package common

import (
	"path/filepath"
	"strings"
)

var (
	KB, MB, GB, TB, PB = 1e3, 1e6, 1e9, 1e12, 1e15
	IgnoredExtensions  = []string{
		// multimedia/containers
		"mp4",
		"avi",
		"mpeg",
		"mpg",
		"mov",
		"wmv",
		"m4p",
		"swf",
		"mp2",
		"flv",
		"vob",
		"webm",
		"hdv",
		"3gp",
		"ogg",
		"mp3",
		"wav",
		"flac",
		"webp",

		// images
		"png",
		"jpg",
		"jpeg",
		"gif",
		"tiff",

		// binaries
		// These can theoretically contain secrets, but need decoding for users to make sense of them, and we don't have
		// any such decoders right now.
		"class",
		"dll",
		"xsb",
		"jdo",
		"jks",
		"ser",
		"idx",
		"hprof",
	}
)

func SkipFile(filename string) bool {
	for _, ext := range IgnoredExtensions {
		if strings.TrimPrefix(filepath.Ext(filename), ".") == ext {
			return true
		}
	}
	return false
}
