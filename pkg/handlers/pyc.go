package handlers

import (
	"bytes"
	"encoding/binary"
)

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

// span is a byte range of string content inside the payload.
type span struct{ start, end int }

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

func isPrintableSpan(b []byte) bool {
	for _, c := range b {
		if !isPrintableASCII(c) {
			return false
		}
	}
	return true
}

// extractPythonBytecodeStrings returns the strings embedded in Python
// bytecode, joined by newlines, arranged so that keyword-prefixed detectors
// can match.
//
// Python's marshal module serializes a code object's co_consts (which hold
// secret values) before its co_names (which hold the identifiers naming
// them), so in raw .pyc bytes a secret always precedes its keyword.
// Detectors built on detectors.PrefixRegex require the keyword to appear
// before the secret, and therefore can never match the raw bytes.
//
// The payload is first parsed structurally as marshal code objects. For each
// code object the identifier spans from co_names are emitted interleaved
// with the value spans from co_consts (names[i] before values[i]), so every
// keyword lands adjacent to the value it names instead of being separated
// from it by unrelated literals. Nested code objects are emitted
// recursively; any spans the structural parse does not claim (bytecode
// sub-runs, filenames, header noise) are appended in file order.
//
// If the payload does not parse as marshal code objects — an unexpected
// version layout, an exotic object type, or anything misaligned — the parse
// is abandoned and the spans fall back to plain reverse file order, which
// still restores the keyword-before-secret arrangement for the common
// single-assignment case.
//
// Strings are located by their marshal framing (type code + length prefix)
// rather than by scanning for printable runs, so each extracted string has
// clean boundaries: the framing bytes that would otherwise glue onto the
// secret and defeat anchored detector patterns are left behind.
func extractPythonBytecodeStrings(data []byte) []byte {
	spans := scanBytecodeSpans(data)
	if len(spans) == 0 {
		return nil
	}
	if out, ok := tryStructuredOrder(data, spans); ok {
		return out
	}
	return joinBytecodeSpansReversed(data, spans)
}

// scanBytecodeSpans collects the content spans of the payload's
// length-delimited string-like marshal objects, in file order.
func scanBytecodeSpans(data []byte) []span {
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
		if !isPrintableSpan(content) {
			i++
			continue
		}

		spans = append(spans, span{start, end})
		// Skip past the consumed string so bytes inside it cannot start an
		// overlapping false-positive match.
		i = end
	}

	return spans
}

// joinBytecodeSpansReversed emits spans in reverse file order. This is the
// fallback arrangement: identifiers (co_names, written last) precede the
// secrets (co_consts, written first) they name.
func joinBytecodeSpansReversed(data []byte, spans []span) []byte {
	out := make([]byte, 0, len(data)/2)
	for k := len(spans) - 1; k >= 0; k-- {
		if k != len(spans)-1 {
			out = append(out, '\n')
		}
		out = append(out, data[spans[k].start:spans[k].end]...)
	}
	return out
}

const (
	// maxMarshalDepth bounds recursion when walking nested marshal objects.
	maxMarshalDepth = 64
	// maxMarshalTupleLen rejects implausible tuple/set element counts.
	maxMarshalTupleLen = 1 << 20
)

// marshalCursor is a bounds-checked reader over marshal payload bytes.
type marshalCursor struct {
	data  []byte
	pos   int
	depth int
}

func (c *marshalCursor) u8() (byte, bool) {
	if c.pos >= len(c.data) {
		return 0, false
	}
	b := c.data[c.pos]
	c.pos++
	return b, true
}

func (c *marshalCursor) u32() (uint32, bool) {
	if c.pos+4 > len(c.data) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(c.data[c.pos : c.pos+4])
	c.pos += 4
	return v, true
}

func (c *marshalCursor) skip(n int) bool {
	if n < 0 || c.pos+n > len(c.data) {
		return false
	}
	c.pos += n
	return true
}

// takeString parses one length-delimited string-like marshal object at the
// cursor. The content span is reported when the bytes pass the same content
// filter as the flat scan; objects that fail the filter are still consumed
// so parsing stays aligned. ok=false means the bytes are not a well-formed
// object and the structural parse must be abandoned.
func (c *marshalCursor) takeString(hdrLen int) (sp span, isContent bool, ok bool) {
	var length uint64
	switch hdrLen {
	case 1:
		b, ok := c.u8()
		if !ok {
			return span{}, false, false
		}
		length = uint64(b)
	case 4:
		v, ok := c.u32()
		if !ok {
			return span{}, false, false
		}
		length = uint64(v)
	default:
		return span{}, false, false
	}
	if length > uint64(len(c.data)-c.pos) {
		return span{}, false, false
	}
	start := c.pos
	c.pos += int(length)
	if length < minPythonStringRun || !isPrintableSpan(c.data[start:c.pos]) {
		return span{}, false, true
	}
	return span{start, c.pos}, true, true
}

// constItem is one parsed element of a co_consts tuple.
type constItem struct {
	str   span        // valid when isStr
	isStr bool        // element is a content string
	code  *codeLayout // valid when the element is a nested code object
	elems []constItem // valid for nested tuple/set elements
}

// codeLayout is the parsed shape of one marshal code object: the identifier
// spans from co_names and the value spans from co_consts, in file order.
type codeLayout struct {
	names   []span
	values  []span // flattened string elements of co_consts, file order
	nested  []*codeLayout
	trailer []span // other content spans of this object (e.g. code bytes)
}

// parseTupleHeader parses a tuple header: either TYPE_TUPLE '(' with a
// 4-byte element count or TYPE_SMALL_TUPLE ')' (marshal version 4+, which
// covers all supported Pythons) with a 1-byte count.
func (c *marshalCursor) parseTupleHeader() (uint64, bool) {
	tb, ok := c.u8()
	if !ok {
		return 0, false
	}
	switch tb & 0x7f {
	case '(':
		n, ok := c.u32()
		if !ok || n > maxMarshalTupleLen {
			return 0, false
		}
		return uint64(n), true
	case ')':
		n, ok := c.u8()
		if !ok {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
}

// parseTuple parses a tuple's elements with elem.
func (c *marshalCursor) parseTuple(elem func() (constItem, bool)) ([]constItem, bool) {
	n, ok := c.parseTupleHeader()
	if !ok {
		return nil, false
	}
	var elems []constItem
	c.depth++
	for i := uint64(0); i < n; i++ {
		it, ok := elem()
		if !ok {
			c.depth--
			return nil, false
		}
		elems = append(elems, it)
	}
	c.depth--
	return elems, true
}

// parseConstElem parses one marshal object in a value position (co_consts or
// a nested tuple). Content strings are returned structurally; nested code
// objects are parsed recursively.
func (c *marshalCursor) parseConstElem() (constItem, bool) {
	if c.depth > maxMarshalDepth {
		return constItem{}, false
	}
	tb, ok := c.u8()
	if !ok {
		return constItem{}, false
	}
	if hdrLen, isStr := marshalStringTypes[tb&0x7f]; isStr {
		sp, isContent, ok := c.takeString(hdrLen)
		if !ok {
			return constItem{}, false
		}
		if isContent {
			return constItem{str: sp, isStr: true}, true
		}
		return constItem{}, true
	}
	switch tb & 0x7f {
	case '(', ')': // tuple / small tuple
		elems, ok := c.parseTuple(c.parseConstElem)
		if !ok {
			return constItem{}, false
		}
		return constItem{elems: elems}, true
	case 'C', 'f': // set, frozenset
		n, ok := c.u32()
		if !ok || n > maxMarshalTupleLen {
			return constItem{}, false
		}
		item := constItem{}
		c.depth++
		for i := uint32(0); i < n; i++ {
			sub, ok := c.parseConstElem()
			if !ok {
				c.depth--
				return constItem{}, false
			}
			item.elems = append(item.elems, sub)
		}
		c.depth--
		return item, true
	case 'c': // code object
		c.depth++
		layout, ok := c.parseCodeBody()
		c.depth--
		if !ok {
			return constItem{}, false
		}
		return constItem{code: layout}, true
	case 'N', 'T', 'F', '.': // None, True, False, Ellipsis
		return constItem{}, true
	case 'i', 'r': // int32, interned-object reference
		if !c.skip(4) {
			return constItem{}, false
		}
		return constItem{}, true
	case 'g': // float
		if !c.skip(8) {
			return constItem{}, false
		}
		return constItem{}, true
	case 'x', 'y': // complex
		if !c.skip(16) {
			return constItem{}, false
		}
		return constItem{}, true
	default:
		// Anything else (notably TYPE_LONG 'l', whose digit encoding is
		// version-sensitive) aborts the structural parse; the caller falls
		// back to reverse file order rather than risk misaligned output.
		return constItem{}, false
	}
}

// parseCodeBody parses a code object; the cursor must be positioned just
// after its type byte. The int32 header held six fields through 3.10 and
// five from 3.11 on (co_nlocals was dropped); both layouts are tried. The
// version-dependent tail after co_names is parsed as well, because nested
// code objects must be consumed in full for the enclosing tuple to stay
// aligned.
func (c *marshalCursor) parseCodeBody() (*codeLayout, bool) {
	if c.depth > maxMarshalDepth {
		return nil, false
	}
	start := c.pos
	// 3.11+ layout: five int32 header fields.
	if layout, ok := c.parseCodeFields(5*4, true); ok {
		return layout, true
	}
	c.pos = start
	// Pre-3.11 layout: six int32 header fields.
	return c.parseCodeFields(6*4, false)
}

// parseNameTuple parses a marshal object in an identifier-tuple position
// (co_names, co_localsplusnames/co_varnames, ...). Tuples contribute their
// string elements; an already-seen tuple written again as a reference is
// tolerated.
func (c *marshalCursor) parseNameTuple() ([]span, bool) {
	tb, ok := c.u8()
	if !ok {
		return nil, false
	}
	switch tb & 0x7f {
	case '(', ')':
		c.pos--
		elems, ok := c.parseTuple(c.parseConstElem)
		if !ok {
			return nil, false
		}
		var names []span
		for _, it := range elems {
			if it.isStr {
				names = append(names, it.str)
			}
		}
		return names, true
	case 'r':
		if !c.skip(4) {
			return nil, false
		}
		return nil, true
	default:
		return nil, false
	}
}

// parseCodeFields parses a code object with the given int32 header size;
// modern selects the 3.11+ tail layout after co_names.
func (c *marshalCursor) parseCodeFields(hdrBytes int, modern bool) (*codeLayout, bool) {
	layout := &codeLayout{}
	if !c.skip(hdrBytes) {
		return nil, false
	}
	// Code bytes object; any content spans it holds go to the trailer.
	codeItem, ok := c.parseConstElem()
	if !ok {
		return nil, false
	}
	collectItemSpans(codeItem, &layout.trailer)
	// co_consts.
	consts, ok := c.parseTuple(c.parseConstElem)
	if !ok {
		return nil, false
	}
	for _, it := range consts {
		flattenItemValues(it, layout)
	}
	// co_names.
	names, ok := c.parseNameTuple()
	if !ok {
		return nil, false
	}
	layout.names = append(layout.names, names...)
	// Version-dependent tail. Its leading tuples hold the remaining
	// identifiers (co_localsplusnames on 3.11+, co_varnames/co_freevars/
	// co_cellvars before that); the rest is filename/name/line-table
	// material for the trailer, with co_firstlineno as a raw int32.
	var nameTuples, trailerBefore, trailerAfter int
	if modern {
		nameTuples, trailerBefore, trailerAfter = 1, 4, 2
	} else {
		nameTuples, trailerBefore, trailerAfter = 3, 2, 1
	}
	for i := 0; i < nameTuples; i++ {
		ns, ok := c.parseNameTuple()
		if !ok {
			return nil, false
		}
		layout.names = append(layout.names, ns...)
	}
	for i := 0; i < trailerBefore; i++ {
		it, ok := c.parseConstElem()
		if !ok {
			return nil, false
		}
		collectItemSpans(it, &layout.trailer)
	}
	if !c.skip(4) { // co_firstlineno
		return nil, false
	}
	for i := 0; i < trailerAfter; i++ {
		it, ok := c.parseConstElem()
		if !ok {
			return nil, false
		}
		collectItemSpans(it, &layout.trailer)
	}
	return layout, true
}

// collectItemSpans appends every content span in item (recursively) to dst.
func collectItemSpans(it constItem, dst *[]span) {
	if it.isStr {
		*dst = append(*dst, it.str)
	}
	if it.code != nil {
		collectLayoutSpans(it.code, dst)
	}
	for _, sub := range it.elems {
		collectItemSpans(sub, dst)
	}
}

// collectLayoutSpans appends every content span owned by a parsed code
// object to dst.
func collectLayoutSpans(l *codeLayout, dst *[]span) {
	*dst = append(*dst, l.names...)
	*dst = append(*dst, l.values...)
	for _, n := range l.nested {
		collectLayoutSpans(n, dst)
	}
	*dst = append(*dst, l.trailer...)
}

// flattenItemValues folds a co_consts element into the layout: content
// strings become values in file order, nested code objects are kept as
// nested layouts, nested tuples are flattened recursively.
func flattenItemValues(it constItem, layout *codeLayout) {
	if it.isStr {
		layout.values = append(layout.values, it.str)
		return
	}
	if it.code != nil {
		layout.nested = append(layout.nested, it.code)
		return
	}
	for _, sub := range it.elems {
		flattenItemValues(sub, layout)
	}
}

// tryStructuredOrder attempts to parse the payload's code objects and emit
// their strings with each object's identifiers before the values they name.
// Every span the parse reports must coincide with a span from the
// independent flat scan; otherwise the parse is treated as misaligned and
// the caller falls back to reverse file order.
func tryStructuredOrder(data []byte, spans []span) ([]byte, bool) {
	flat := make(map[span]bool, len(spans))
	for _, s := range spans {
		flat[s] = true
	}
	for i := 0; i < len(data); i++ {
		if data[i]&0x7f != 'c' || spanCovers(spans, i) {
			continue
		}
		cur := &marshalCursor{data: data, pos: i + 1}
		layout, ok := cur.parseCodeBody()
		if !ok {
			continue
		}
		var reported []span
		collectLayoutSpans(layout, &reported)
		aligned := true
		for _, s := range reported {
			if !flat[s] {
				aligned = false
				break
			}
		}
		if !aligned {
			continue
		}
		return emitStructured(data, layout, spans), true
	}
	return nil, false
}

// spanCovers reports whether offset i lies inside any span. spans must be in
// file order and non-overlapping, which the flat scan guarantees.
func spanCovers(spans []span, i int) bool {
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := (lo + hi) / 2
		if spans[mid].start > i {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	if lo == 0 {
		return false
	}
	s := spans[lo-1]
	return i < s.end
}

// emitStructured writes each code object's identifiers interleaved with the
// values they name (names[i] before values[i]), then nested code objects,
// then trailer spans. Flat-scan spans the parse did not claim are appended
// in file order.
func emitStructured(data []byte, layout *codeLayout, spans []span) []byte {
	claimed := make(map[span]bool)
	var parts [][]byte
	emit := func(s span) {
		claimed[s] = true
		parts = append(parts, data[s.start:s.end])
	}
	var walk func(l *codeLayout)
	walk = func(l *codeLayout) {
		ni, vi := 0, 0
		for ni < len(l.names) || vi < len(l.values) {
			if ni < len(l.names) {
				emit(l.names[ni])
				ni++
			}
			if vi < len(l.values) {
				emit(l.values[vi])
				vi++
			}
		}
		for _, n := range l.nested {
			walk(n)
		}
		for _, s := range l.trailer {
			emit(s)
		}
	}
	walk(layout)
	for _, s := range spans {
		if !claimed[s] {
			parts = append(parts, data[s.start:s.end])
		}
	}
	return bytes.Join(parts, []byte{'\n'})
}
