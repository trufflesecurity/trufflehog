package common

import (
	"path/filepath"
	"strings"
)

var (
	KB, MB, GB, TB, PB = 1e3, 1e6, 1e9, 1e12, 1e15
	ignoredExtensions  = map[string]struct{}{
		// images
		"apng": {},
		"avif": {},
		"bmp":  {},
		"gif":  {},
		"icns": {}, // Apple icon image file
		"ico":  {}, // Icon file
		"jpg":  {},
		"jpeg": {},
		"png":  {},
		"svg":  {},
		"svgz": {}, // Compressed Scalable Vector Graphics file
		"tga":  {},
		"tif":  {},
		"tiff": {},

		// audio
		"fev":  {}, // video game audio
		"fsb":  {},
		"m2a":  {},
		"m4a":  {},
		"mp2":  {},
		"mp3":  {},
		"snag": {},

		// video
		"264":  {},
		"3gp":  {},
		"avi":  {},
		"flac": {},
		"flv":  {},
		"hdv":  {},
		"m4p":  {},
		"mov":  {},
		"mp4":  {},
		"mpg":  {},
		"mpeg": {},
		"ogg":  {},
		"qt":   {},
		"swf":  {},
		"vob":  {},
		"wav":  {},
		"webm": {},
		"webp": {},
		"wmv":  {},

		// documents
		"pdf": {},
		"psd": {},

		// fonts
		"eot":   {}, // Embedded OpenType font
		"fnt":   {}, // Windows font file
		"fon":   {}, // Generic font file
		"otf":   {}, // OpenType font
		"ttf":   {}, // TrueType font
		"woff":  {}, // Web Open Font Format
		"woff2": {}, // Web Open Font Format 2
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
		"pyo":    {}, // Compiled Python file
		"pyc":    {}, // Compiled Python file
		"sym":    {}, // Symbolic link, Unix/Linux
	}
)

// SkipFile returns true if the file extension is in the ignoredExtensions list.
func SkipFile(filename string) bool {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))
	_, ok := ignoredExtensions[ext]
	return ok
}

// IsBinary returns true if the file extension is in the binaryExtensions list.
func IsBinary(filename string) bool {
	_, ok := binaryExtensions[strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))]
	return ok
}
