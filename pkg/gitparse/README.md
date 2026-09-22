# gitparse

`gitparse` turns a git repository's history into a stream of `*Diff` values, one for each
changed file in each commit. It is the front door for the git based sources: everything
TruffleHog scans out of a repository's history comes through this package.

It works by running the `git` binary and reading its text output, rather than reading
git's object files directly. Parsing text is not pretty, but `git log --patch` already
handles renames, binary files, path filters and merges, and rewriting all of that
ourselves would be a much bigger thing to get wrong.

## What comes out

A `Diff` is one file's added content inside one commit, along with the details of that
commit:

```go
diffChan, err := parser.RepoPath(ctx, repoPath, "", true, nil, false)
for diff := range diffChan {
    diff.Commit.Hash    // the commit this change belongs to
    diff.PathB          // the path of the changed file
    diff.LineStart      // where in the file the hunk starts
    diff.ReadCloser()   // the added lines, and nothing else
}
```

Only added lines are kept. Removed and unchanged lines are thrown away, because a secret
that was deleted was already there in the commit that added it, and that commit is in the
stream too.

Commit details are attached to every diff. A commit with no file changes at all, such as
a merge or an empty commit, is still sent once on its own, because its message, author and
notes can hold a secret even when no file changed.

Diff content goes to one of two writers, chosen by the caller. `buffer_writer` keeps it in
memory and is the default. `buffered_file_writer` spills to disk past a size and is turned
on with `UseCustomContentWriter`. Repositories with big files want the second one.

## How the log is produced

There are two ways, and the caller picks.

**The normal way** is one `git log --patch` for the whole repository. Simple, fast, and
fine for most repositories.

**The lower memory way** is turned on with `UseLowMemoryScan`, which the CLI exposes as
`--git-low-memory-scan`. It exists because one `git log --patch` keeps a little state for
every commit it walks and never gives any of it back, so on a repository with millions of
commits it grows until the machine kills it.

That mode splits the work in two:

1. **List the commits.** `git rev-list` prints the hashes we want and nothing else. The
   hashes come back in groups, so the next step can start before the whole history has
   been walked.

2. **Make the patches.** Each group of hashes is handed to its own short lived `git log`
   process, which reads them on standard input. Each process only holds state for its own
   group and then exits, so this step costs the same no matter how long the history is.

The results of all those processes are joined back into the single channel the caller
sees, so nothing above this package needs to know which way was used.

## Things that look like details but are not

Each of these came from a test or a measurement that said otherwise.

**Listing uses `git rev-list`, not `git log`.** They can both print hashes, but `git log`
sets up git's diff machinery as soon as a diff option is present, and then compares files
in every commit just to decide which commits to print. `rev-list` never does that. This is
the step that uses the most memory on long histories, so the difference matters, and it is
large.

**Diff options stay out of the listing step.** Options like `--diff-filter=AM` live with
the patch options, not the commit picking options. `rev-list` rejects them anyway. Leaving
them out means the listing picks up a few extra commits whose changes are all filtered
away, and the `git log` that makes the patches drops those commits itself, exactly as the
single command form does. The end result is the same commits, worked out in the cheaper
place.

**Patches come from `git log --no-walk=unsorted`, not `git show`.** They print the same
thing for ordinary commits, but only `git log` applies `--diff-filter` to whole commits,
so using `git show` here would scan more commits than the normal way does. `unsorted`
matters too: plain `--no-walk` re-sorts each group by commit date, which scrambles the
order across groups.

**Hashes go in on standard input, not as arguments.** A command line has a length limit,
and on Windows it is short enough to cap a group at a few dozen commits. Standard input
has no such limit, so groups can be thousands of commits and full hashes can be used
instead of shortened ones. Fewer, bigger groups mean fewer git processes to start.

**Path filters go to both steps.** The listing needs them to pick the same commits the
single command would have shown, and the patch step needs them to decide which files show
up.

**The last commit of a stream needs finishing off.** The parser normally completes a
commit when it sees the next one begin. The last commit never gets that, so it is
completed at the end of the stream instead. Without this, a commit with no file changes
was dropped whenever it landed at the end, which used to be rare with one long stream and
became common once the log was split into groups.

## Stopping early

A scan can stop before the diffs run out, when it hits its maximum depth or reaches its
base commit. A Go channel cannot tell you that its reader has gone away, so the scan
cancels its context on the way out, and that is what shuts down the git processes still
producing diffs.

Cancelling also keeps the listing step short. It only ever runs a few groups ahead of what
is being consumed, because the channels between the steps are unbuffered, so a scan that
stops early never walks the whole history.

## Tests

```sh
go test ./pkg/gitparse/
```

The tests in `lowmemory_test.go` hold the lower memory mode to one rule: it must produce
exactly what the single command form produces, with the same commits, paths and content,
wherever the group boundaries land. They run with tiny group sizes on purpose, since a
group size of one puts every commit at the end of a stream at once, which is where the
awkward cases live.
