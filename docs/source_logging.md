# Logging in sources

These rules are for code in `pkg/sources`. Every source should follow them, so that debug logs look the same in
every source and never leak anything sensitive. The general logging guidelines in
[CONTRIBUTING.md](../CONTRIBUTING.md#logging-in-trufflehog) still apply.

## Levels

| Level  | Use it for                                                                     |
|--------|--------------------------------------------------------------------------------|
| `V(0)` | Things a user should see: scan start and end, totals, warnings.                |
| `V(1)` | Lifecycle: source init, enumeration start and end, config choices.             |
| `V(2)` | One line per unit: a repo, bucket, project, channel, or site.                  |
| `V(3)` | One line per item in a unit: a file, object, commit, page, or message.         |
| `V(4)` | Decisions and API detail: skips and why, pages, retries, rate limits.          |
| `V(5)` | Debug: request and response summaries, internal state, timings.                |

Errors are logged with `Error(err, ...)`, not with `Info` and an error field.

## Never log

- Secrets, tokens, passwords, or API keys.
- Auth headers, or URLs with credentials in them.
- Raw chunk data.

Logs are redacted for known secrets, but that is a safety net, not permission. Debug logs may include item names,
paths, and URLs, so think about what a line could contain before adding it.

## Use the logger from the context

- Log with `ctx.Logger()` from the context passed into the current call.
- Don't store a `logr.Logger` in a struct. A stored logger misses the fields and the log level that were set on the
  context, including per-source debug.
- Don't create `context.Background()` or `context.TODO()` inside a source. Pass the context you were given.
- Use key/value pairs, not format strings. Add fields that apply to a whole block of work with
  `context.WithValues`.
- If building a debug line is expensive, check `ctx.Logger().V(5).Enabled()` first.

## Per-source debug

Debug logging can be turned on for a single source while every other source keeps the normal log level. This works
through the context: `context.WithLogLevel(ctx, log.DebugLevel)` returns a context whose logger writes everything up
to `V(5)`. Any code that logs through `ctx.Logger()` gets this for free, which is one more reason not to store
loggers.

## Testing

Use `logtest.DebugContext()` to run a source with debug turned on and look at what it logged:

```go
ctx, logs := logtest.DebugContext()
err := s.Init(ctx, "test source", 0, 0, false, conn, 1)
require.NoError(t, err)

assert.Equal(t, 1, logs.FilterMessage("listing repositories").Len())
for _, entry := range logs.All() {
	assert.NotContains(t, entry.Message, testSecret)
}
```
