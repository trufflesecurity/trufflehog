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

1. Make a lowercased copy of the chunk, so matching ignores case.
2. Walk the copy once and collect every keyword hit.
3. For each hit, work out a **span**: a window of bytes around it, cut from the
   original chunk. Detectors get this window rather than the whole chunk, which
   keeps their regexes fast. Some detectors ask for a wider window, for example
   when a credential comes in two parts that may sit on separate lines.
4. Return one entry per matching detector, with its spans merged.

## Lowercasing only A-Z

Step 1 lowercases `A-Z` by hand and leaves every other byte untouched, rather
than using `bytes.ToLower`.

The reason is step 3. Positions come from the lowercased copy, but the bytes are
cut from the original chunk. That only lines up while both are the same length.

Full Unicode lowercasing does not promise that. Some characters need a different
number of bytes once lowercased — `İ` takes two bytes, `i` takes one. A single
one of those makes the copy shorter, so every position after it points slightly
too far back, and a detector is handed text that is not the text that matched.

Changing only `A-Z` always keeps the same length, so positions stay correct.

Keywords are folded through the same function when they are registered, so both
sides of the search always agree.

### Known limitation

A cased non-ASCII letter is left exactly as written, on both sides. So a keyword
containing one matches only text spelling that letter the same way: a keyword
`CAFÉ` matches `CAFÉ` but not `café`.

Every built-in detector keyword is plain ASCII, so this cannot affect them, and
a test checks that assumption still holds. It only applies to a custom detector
using a non-ASCII keyword.

## The buffer pool

Every chunk needs its own lowercased copy, and each copy is discarded moments
later. Allocating a fresh one each time would mean throwing away a chunk-sized
buffer on every call, for every chunk in a scan.

Instead the copies come from `lowerBufPool`, a small pool of reusable buffers:

- `getLowerBuf` borrows one, growing it only if the chunk does not fit.
- `putLowerBuf` hands it back once the chunk is done with.

In a steady scan the pool already holds a buffer large enough, so making the copy
costs **no allocation at all**. Buffers larger than `maxPooledLowerBuf` are
dropped rather than kept, so one unusually big chunk cannot leave a large buffer
parked in the pool for the rest of the run.

## What it costs

`BenchmarkLowerBuf` compares borrowing a buffer from the pool against building a
fresh lowercased copy each time. On an Apple M3 Pro:

```
BenchmarkLowerBuf/pooled-11       245199   4929 ns/op   1866.34 MB/s      0 B/op   0 allocs/op
BenchmarkLowerBuf/unpooled-11     225938   5097 ns/op   1805.07 MB/s   9472 B/op   1 allocs/op
```

The time difference is small enough to be run-to-run noise. What the pool
actually removes is the allocation: **9472 B and 1 allocation per chunk, down to
zero**. That copy would otherwise be made and thrown away for every chunk in a
scan, so the saving grows with the amount of data scanned rather than showing up
on the clock here.

Reproduce with:

```sh
go test ./pkg/engine/ahocorasick/ -bench=BenchmarkLowerBuf -benchmem
```
