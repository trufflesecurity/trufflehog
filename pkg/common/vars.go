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

		"fnt",   // Windows font file
		"fon",   // Generic font file
		"ttf",   // TrueType font
		"otf",   // OpenType font
		"woff",  // Web Open Font Format
		"woff2", // Web Open Font Format 2
		"eot",   // Embedded OpenType font
		"svgz",  // Compressed Scalable Vector Graphics file
		"icns",  // Apple icon image file
		"ico",   // Icon file
	}

	binaryExtensions = map[string]struct{}{
		// binaries
		// These can theoretically contain secrets, but need decoding for users to make sense of them, and we don't have
		// any such decoders right now.
		"class":  {}, // Java bytecode class file
		"dll":    {}, // Dynamic Link Library, Windows
		"jdo":    {}, // Java Data Object, Java serialization format
		"jks":    {}, // Java Key Store, Java keystore format
		"ser":    {}, // Java serialization format
		"idx":    {}, // Index file, often binary
		"hprof":  {}, // Java heap dump format
		"exe":    {}, // Executable, Windows
		"bin":    {}, // Binary, often used for compiled source code
		"so":     {}, // Shared object, Unix/Linux
		"o":      {}, // Object file from compilation/ intermediate object file
		"a":      {}, // Static library, Unix/Linux
		"dylib":  {}, // Dynamic library, macOS
		"lib":    {}, // Library, Unix/Linux
		"obj":    {}, // Object file, typically from compiled source code
		"pdb":    {}, // Program Database, Microsoft Visual Studio debugging format
		"dat":    {}, // Generic data file, often binary but not always
		"elf":    {}, // Executable and Linkable Format, common in Unix/Linux
		"dmg":    {}, // Disk Image for macOS
		"iso":    {}, // ISO image (optical disk image)
		"img":    {}, // Disk image files
		"out":    {}, // Common output file from compiled executable in Unix/Linux
		"com":    {}, // DOS command file, executable
		"sys":    {}, // Windows system file, often a driver
		"vxd":    {}, // Virtual device driver in Windows
		"sfx":    {}, // Self-extracting archive
		"bundle": {}, // Mac OS X application bundle
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

// IsBinary returns true if the file extension is in the binaryExtensions list.
func IsBinary(filename string) bool {
	_, ok := binaryExtensions[strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))]
	return ok
}
