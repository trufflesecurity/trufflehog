# ahocorasick

This package decides **which detectors are worth running on a piece of data**.

## Why it exists

TruffleHog ships hundreds of detectors. Running every one against every chunk of
scanned data would be far too slow, and almost always pointless: a file about
billing has nothing to do with a Kubernetes token.

So each detector declares a few keywords it cares about. A SendGrid key always
contains `SG.`, so the SendGrid detector only needs to see chunks containing
`SG.`. This package checks the whole keyword list in one pass and reports which
detectors matched. Everything else is skipped.

That check is a **prefilter**: a cheap test run before the expensive one.

## How it works

The [Aho-Corasick algorithm](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
searches for many words at once. Rather than scanning the text once per keyword,
it builds a lookup structure from every keyword up front, then walks the text a
single time. The cost barely changes whether there are ten keywords or ten
thousand.

`FindDetectorMatches` does the work:

1. Walk the chunk once and collect every keyword hit, ignoring case.
2. For each hit, work out a **span**: a window of bytes around it, cut from the
   chunk. Detectors get this window rather than the whole chunk, which keeps
   their regexes fast. Some detectors ask for a wider window, for example when a
   credential comes in two parts that may sit on separate lines.
3. Return one entry per matching detector, with its spans merged.

## The keyword trie

`keywordTrie` builds the Aho-Corasick table with every transition worked out up
front, so the walk reads exactly one table entry per byte.

Each byte that appears in some keyword gets its own column in the table. Every
other byte shares a single column. With the built-in keywords that is about 50
columns instead of 256, so the table stays small enough to sit in the CPU cache.

`A-Z` share the columns of `a-z`. That is how matching ignores case: there is no
lowercased copy of the chunk, so positions always point into the chunk itself.

Two details keep the walk short. Each cell stores the next state as the offset
of its row (state number times the number of columns), so no multiply is needed
per byte. And states that end a keyword are numbered after all the others, so
checking for a match is one comparison rather than a lookup per byte.

## Folding only A-Z

Only `A-Z` is folded, on both sides. Keywords are folded by `appendASCIILower`
when they are registered, and the trie folds chunk bytes the same way as it
reads them, so the two sides always agree.

Every other byte must match exactly. Full Unicode lowercasing is not used: some
characters change byte length when lowercased (`İ` takes two bytes, `i` takes
one), and nothing would be gained, since every built-in keyword is plain ASCII.

### Known limitation

A cased non-ASCII letter is left exactly as written, on both sides. So a keyword
containing one matches only text spelling that letter the same way: a keyword
`CAFÉ` matches `CAFÉ` but not `café`.

Every built-in detector keyword is plain ASCII, so this cannot affect them, and
a test checks that assumption still holds. It only applies to a custom detector
using a non-ASCII keyword.

## Measuring it

```sh
go test ./pkg/engine/ahocorasick/ -run '^$' -bench BenchmarkFindDetectorMatches -benchmem
```
