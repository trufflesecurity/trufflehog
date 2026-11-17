package ahocorasick

// keywordTrie finds every keyword in a piece of data in a single pass.
//
// Every transition is worked out when the trie is built, so matching reads one
// table entry per input byte. Bytes that appear in no keyword share one column
// of the table, which keeps it small enough to stay in the CPU cache.
//
// A-Z share the columns of a-z, so matching ignores ASCII case without making a
// lowercased copy of the data. Every other byte must match exactly.
type keywordTrie struct {
	classes  [256]uint32
	nclasses uint32
	// next stores each state as its row's offset (state number times
	// nclasses), so the walk needs no multiply. It is unsigned so the index
	// needs no sign handling. Both are measurably faster.
	next []uint32
	// States that end a keyword are numbered last, so finding a match is a
	// single comparison. The keywords ending at the k-th such state, longest
	// first, are outputs[outStart[k]:outStart[k+1]].
	firstMatch uint32
	outStart   []int32
	outputs    []string
}

func newKeywordTrie(keywords []string) *keywordTrie {
	t := &keywordTrie{nclasses: 1}
	for _, kw := range keywords {
		for i := 0; i < len(kw); i++ {
			c := asciiLower(kw[i])
			if t.classes[c] == 0 {
				t.classes[c] = t.nclasses
				t.nclasses++
			}
		}
	}
	for c := byte('A'); c <= 'Z'; c++ {
		t.classes[c] = t.classes[asciiLower(c)]
	}

	newRow := func() []int32 {
		row := make([]int32, t.nclasses)
		for i := range row {
			row[i] = -1
		}
		return row
	}
	rows := [][]int32{newRow()}
	ends := []string{""}
	for _, kw := range keywords {
		if kw == "" {
			continue
		}
		s := int32(0)
		for i := 0; i < len(kw); i++ {
			c := t.classes[kw[i]]
			if rows[s][c] == -1 {
				rows = append(rows, newRow())
				ends = append(ends, "")
				rows[s][c] = int32(len(rows) - 1)
			}
			s = rows[s][c]
		}
		ends[s] = kw
	}

	fail := make([]int32, len(rows))
	outs := make([][]string, len(rows))
	var queue []int32
	for c, child := range rows[0] {
		if child == -1 {
			rows[0][c] = 0
			continue
		}
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if ends[s] != "" {
			outs[s] = append(outs[s], ends[s])
		}
		outs[s] = append(outs[s], outs[fail[s]]...)
		for c, child := range rows[s] {
			if child == -1 {
				rows[s][c] = rows[fail[s]][c]
				continue
			}
			fail[child] = rows[fail[s]][c]
			queue = append(queue, child)
		}
	}

	// Renumber: states that end no keyword first, starting with the root,
	// then the ones that do.
	order := make([]int32, 0, len(rows))
	for s := range rows {
		if len(outs[s]) == 0 {
			order = append(order, int32(s))
		}
	}
	t.firstMatch = uint32(len(order)) * t.nclasses
	for s := range rows {
		if len(outs[s]) > 0 {
			order = append(order, int32(s))
		}
	}
	offset := make([]uint32, len(rows))
	for n, s := range order {
		offset[s] = uint32(n) * t.nclasses
	}

	t.next = make([]uint32, 0, len(rows)*int(t.nclasses))
	t.outStart = []int32{0}
	for _, s := range order {
		for _, target := range rows[s] {
			t.next = append(t.next, offset[target])
		}
		if len(outs[s]) > 0 {
			t.outputs = append(t.outputs, outs[s]...)
			t.outStart = append(t.outStart, int32(len(t.outputs)))
		}
	}
	return t
}

// walk calls fn for every keyword found in data, with the position where it
// starts. Matches come in order of where they end, longest first.
func (t *keywordTrie) walk(data []byte, fn func(start int64, keyword string)) {
	s := uint32(0)
	for i, b := range data {
		s = t.next[s+t.classes[b]]
		if s >= t.firstMatch {
			k := (s - t.firstMatch) / t.nclasses
			for _, kw := range t.outputs[t.outStart[k]:t.outStart[k+1]] {
				fn(int64(i-len(kw)+1), kw)
			}
		}
	}
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
