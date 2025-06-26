# Contribution guidelines

Please create an issue to collect feedback prior to feature additions. If possible try to keep PRs scoped to one feature, and add tests for new features. We use the fork-based contribution model described by [GitHub's documentation](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project). (In short: Fork the TruffleHog repo and open a PR back from your fork into our default branch.)

When showing interest in a bug, enhancement, PR, or issue, please use the thumbs up/thumbs down emoji on the original message rather than adding comments expressing the same.

Contributors need to [sign our CLA](https://cla-assistant.io/trufflesecurity/trufflehog) before we are able to accept contributions.

# Resources

## How things work

It can be a bit daunting diving into the code and wrapping your head around the project from a high level.  The following two docs help give that high level overview:
* [Process Flow](docs/process_flow.md)
* [Concurrency Overview](docs/concurrency.md)

## Adding new secret detectors

We have published some [documentation and tooling to get started on adding new secret detectors](hack/docs/Adding_Detectors_external.md). Let's improve detection together!

## Logging in TruffleHog

**Use fields over format strings**. For structured logging, fields allow us to better filter and search through logs than embedding data in the message.

**Differentiate logs coming from dependencies**. This can be done with a `"dep"` field that gets passed to the library. Sometimes it’s not possible to do this.

Limit log levels to _**info**_ (indicate normal or expected operation) and _**error**_ (functionality is impeded and should be checked by an engineer)

**Choose an appropriate verbosity level**
```
0. — logs we always want to see
1. — logs we could possibly want to turn off
2. — logs that are useful for debugging
3. — frequently called logs that may produce a lot of output
4. — extremely verbose logs or logs containing sensitive information
5. — ultimate verbosity
```
Example: `Logger().V(2).Info("skipping file: extension is ignored", "ext", mimeExt)`

**Either log an error or return it**. Doing one or the other will help defer logging for when there is more context for it and prevent duplicate “bubbling up” logs.

**Log contextual information**. Every log emitted should contain this context via fields to easily filter and search.
