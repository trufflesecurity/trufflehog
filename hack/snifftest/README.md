# snifftest

See the help pages with this command, or look further below to get started quickly.

```
go run snifftest/main.go 
```

## Show available secret scanners

```
go run snifftest/main.go show-scanners 
```

## Load a repo into a DB

```
go run snifftest/main.go load --db ~/sdb --repo https://github.com/Netflix/Hystrix.git  
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