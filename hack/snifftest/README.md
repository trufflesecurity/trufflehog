# snifftest

See the help pages with this command, or look further below to get started quickly.

```
go run hack/snifftest/main.go
```

## Show available secret scanners

```
go run hack/snifftest/main.go show-scanners
```

## Scan

All scanners

```
go run snifftest/main.go scan --db ~/sdb --scanner all --print
```

Particular scanner

```
go run snifftest/main.go scan --db ~/sdb --scanner github --print --print-chunk --fail-threshold 5
```
