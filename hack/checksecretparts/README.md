# checksecretparts

Static analysis check that finds detector packages which construct
`detectors.Result` values without populating the `SecretParts` field.

## What it checks

For each directory under `pkg/detectors/` (recursing into subpackages):

1. Find every composite literal of the form `detectors.Result{...}` or
   `&detectors.Result{...}` in non-test `.go` files.
2. If the package does not mention `SecretParts` anywhere, emit a warning
   for each construction site.

## Running locally

```sh
# Warning mode (default): prints findings, always exits 0 unless scanning fails.
go run ./hack/checksecretparts

# Scan specific directories instead of ./pkg/detectors.
go run ./hack/checksecretparts ./pkg/detectors/aws ./pkg/detectors/github

# Fail mode: exit 1 if any findings are reported. Use this once every detector
# has been migrated to populate SecretParts.
go run ./hack/checksecretparts -fail
```

## Flipping warning → fail

Once every detector populates `SecretParts`, make this check gating:

1. In `.github/workflows/lint.yml`, drop `continue-on-error: true` from the
   `checksecretparts` job and change the run step to pass `-fail`.
2. Land any remaining migrations in the same PR as the flip.

## Scope limits

- It is a syntactic check. It matches `detectors.Result` by selector-expr
  name; packages that rename the import (`d "...detectors"`) would not be
  caught. No such rename exists in the current codebase.
