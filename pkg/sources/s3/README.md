# S3 source

Scans objects in S3 buckets, or in any S3-compatible service.

## Scan paths

The source implements both the plain `Source` interface and `SourceUnitEnumChunker`, where one unit is one bucket (plus the role used to reach it).

- `Chunks` walks every bucket in sequence.
- `Enumerate` reports each bucket as a unit, and `ChunkUnit` scans one bucket.

Both end up in `scanBucket` -> `pageChunker`, so per-object behavior is identical either way. The CLI always takes the unit path, because `main.go` enables source units and the source supports them.

## Credentials

Set by which flags are present:

| Flags | Credentials used |
| --- | --- |
| none | anonymous, for public buckets only |
| `--cloud-environment` | the AWS SDK's normal chain: env vars, `~/.aws/credentials`, instance metadata |
| `--key` and `--secret` | those static credentials |
| `--key`, `--secret`, `--session-token` | those temporary credentials |

The default is anonymous, not your local AWS profile. Scanning a private bucket without `--cloud-environment` or explicit keys gives `403 AccessDenied`.

`--role-arn` assumes a role before scanning, and can be repeated. With roles and no `--bucket`, the source tries every bucket each role can list, so `AccessDenied` on buckets a role cannot reach is expected and does not fail the scan.

## Choosing buckets

`--bucket` scans only the named buckets. `--ignore-bucket` scans everything else. They cannot be combined; doing so fails at startup. Bucket names are matched exactly, not as globs or prefixes.

## Choosing objects within a bucket

Four flags, all repeatable, all matched against the object key before the object is downloaded. A skipped object costs no `GetObject` request.

- `--include-prefix` / `--exclude-prefix` match a literal key prefix. They can be used together to scan a subtree while leaving part of it out, and an exclude match always wins.
- `--include-extension` / `--exclude-extension` match the file extension, written without a leading dot. They cannot be used together, since listing what to scan already excludes everything else. Matching is case insensitive.

Prefixes are literal, so `--include-prefix=log` matches `logs/app.txt` and `logs-archive/app.txt` alike.

The two kinds are combined with AND: an object has to pass both to be scanned. A key with no extension, like `Makefile`, matches no extension entry, so `--include-extension` skips it and `--exclude-extension` keeps it.

## Objects skipped regardless of configuration

- Glacier and Glacier Instant Retrieval storage classes
- Larger than `--max-object-size`, which defaults to 250 MiB and cannot be raised above it
- Empty
- Extensions in the shared deny list in `pkg/common/vars.go`, which already covers images, audio, and video
- Keys ending in `/`, which are directory markers

## Custom endpoints

`--endpoint` points the scan at an S3-compatible service instead of AWS S3. Setting it changes three things:

- The client uses path-style addressing, since these services rarely publish the wildcard DNS that virtual-hosted addressing needs.
- Per-bucket region discovery is skipped. `GetBucketRegion` is AWS-only, and a custom endpoint serves its own buckets, so requests sign with `--region` instead.
- Object links in finding metadata point at the endpoint rather than `amazonaws.com`, so they resolve the way the scan read them.

The endpoint is parsed in `Init`, so a malformed one fails at startup rather than as an SDK error mid-scan. A missing scheme is assumed to be `https`.

`--region` sets the region used to sign requests and defaults to `us-east-1`. On AWS each bucket's real region is discovered automatically, so it mostly matters with a custom endpoint.

## Resumption

`Checkpointer` tracks which objects in the current page of up to 1000 have finished, and records the highest consecutively completed key as `StartAfter` in `Progress.EncodedResumeInfo`, along with the bucket and role. An interrupted scan resumes from there.

Only consecutive completions are checkpointed. If objects 0 to 5 and 7 to 8 are done but 6 is not, the checkpoint stops at 5, so resuming may rescan a few objects but never misses one.

This matters when adding a new skip to `pageChunker`: a skipped object still has to call `UpdateObjectCompletion`. Skipping without it stalls the checkpoint at the first skipped object, and a resumed scan then redoes everything after it.

The OSS CLI does not persist progress between runs, so resumption only takes effect where something stores and returns `EncodedResumeInfo`.
