package handlers

import "encoding/binary"

// isPythonBytecodeExt reports whether a content-detected file extension is
// Python bytecode. The mimetype library detects bytecode by its magic bytes,
// so this fires regardless of the file's actual name or extension.
func isPythonBytecodeExt(ext string) bool {
	switch ext {
	case ".pyc", ".pyo":
		return true
	default:
		return false
	}
}

// minPythonStringRun is the minimum length of an embedded string extracted
// from Python bytecode. Shorter runs are marshal framing noise rather than
// plausible secret or identifier content.
const minPythonStringRun = 4

// marshalStringTypes are the marshal type codes (low 7 bits; the high bit is
// FLAG_REF) that prefix length-delimited string-like objects. The value is
// the size of the length field that follows the type byte.
var marshalStringTypes = map[byte]int{
	's': 4, // bytes
	'z': 1, // short ASCII-only str
	'Z': 1, // short ASCII-only interned str
	'a': 4, // ASCII-only str
	'A': 4, // ASCII-only interned str
	'u': 4, // unicode str
	't': 4, // interned str
}

// isPrintableASCII reports whether b is a printable ASCII byte.
func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b < 0x7f
}

// extractPythonBytecodeStrings returns the strings embedded in Python
// bytecode in reverse order, joined by newlines.
//
// Python's marshal module serializes a code object's co_consts (which hold
// secret values) before its co_names (which hold the identifiers naming
// them), so in raw .pyc bytes a secret always precedes its keyword.
// Detectors built on detectors.PrefixRegex require the keyword to appear
// before the secret, and therefore can never match the raw bytes. Emitting
// the embedded strings in reverse order restores the keyword-before-secret
// arrangement those detectors expect.
//
// Strings are located by their marshal framing (type code + length prefix)
// rather than by scanning for printable runs, so each extracted string has
// clean boundaries: the framing bytes that would otherwise glue onto the
// secret and defeat anchored detector patterns are left behind.
func extractPythonBytecodeStrings(data []byte) []byte {
	// Collect content spans in file order.
	type span struct{ start, end int }
	var spans []span

	for i := 0; i < len(data); {
		hdrLen, ok := marshalStringTypes[data[i]&0x7f]
		if !ok {
			i++
			continue
		}

		var strLen int
		switch hdrLen {
		case 1:
			if i+1 >= len(data) {
				i++
				continue
			}
			strLen = int(data[i+1])
		case 4:
			if i+5 > len(data) {
				i++
				continue
			}
			strLen = int(binary.LittleEndian.Uint32(data[i+1 : i+5]))
		}

		start, end := i+1+hdrLen, i+1+hdrLen+strLen
		if strLen < minPythonStringRun || end > len(data) {
			i++
			continue
		}
		content := data[start:end]
		printable := true
		for _, b := range content {
			if !isPrintableASCII(b) {
				printable = false
				break
			}
		}
		if !printable {
			i++
			continue
		}

		spans = append(spans, span{start, end})
		// Skip past the consumed string so bytes inside it cannot start an
		// overlapping false-positive match.
		i = end
	}

	// Emit in reverse file order so identifiers (co_names, written last)
	// precede the secrets (co_consts, written first) they name.
	out := make([]byte, 0, len(data)/2)
	for k := len(spans) - 1; k >= 0; k-- {
		if k != len(spans)-1 {
			out = append(out, '\n')
		}
		out = append(out, data[spans[k].start:spans[k].end]...)
	}
	return out
}
