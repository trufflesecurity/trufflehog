# Implementing Analyzers

## Defining the Permissions

Permissions can be defined in:
- lower snake case as `permission_name:access_level`
- kebab case as `permission-name:read`
- dot notation as `permission.name:read`

The Permissions are initially defined as a [yaml file](analyzers/twilio/permissions.yaml).

At the top of the [analyzer implementation](analyzers/twilio/twilio.go) you specify the go generate command.

You can install the generator with `go install github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/generate_permissions`.

Then you can run `go generate ./...` to generate the Permission types for the analyzer.

The generated Permission types are to be used in the `AnalyzerResult` struct when defining the `Permissions` and in your code.
