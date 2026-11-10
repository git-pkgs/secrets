# secrets

`secrets` finds leaked credentials across Git history. It scans repository
blobs with the Betterleaks rule corpus, applies path filters to each blob
occurrence, and attributes findings to commits and paths.

## Build

Requires Go 1.26 or later. The default build embeds a compiled pattern
database for the [git-pkgs/scan](https://github.com/git-pkgs/scan) prefilter
and uses Go's standard regexp package for rule matching. It has no native
library dependencies:

```sh
CGO_ENABLED=0 go build -o secrets .
```

The `gohs` build uses a Hyperscan prefilter with the same regexp package.
It requires CGo, `pkg-config`, and a Hyperscan-compatible library that
exports `libhs`, such as Hyperscan or VectorScan:

```sh
go build -tags gohs -o secrets .
```

Release archives use the default backend and include binaries for Linux,
macOS, and Windows on amd64 and arm64, plus checksums and a Cosign signature
bundle for the checksums.

## Usage

Scan the current repository or pass another repository path:

```sh
./secrets scan
./secrets scan /path/to/repository
```

Pass `--dir` to scan the files in a plain directory instead, such as an
extracted archive or a vendored tree:

```sh
./secrets scan --dir /path/to/directory
```

A directory scan reads regular files only and doesn't follow symlinks. Paths
are relative to the directory, path rules and `--max-blob-size` apply as they
do for a repository, and there is no commit. The blob column holds the Git
blob ID of the file's content, the same ID a repository scan reports.

Findings are written to standard output, and progress and summary statistics,
including the active prefilter engine, to standard error. A clean scan exits
with status 0, while a scan with findings exits with status 1 by default. Use
`--exit-code` to choose another finding status, or `--exit-code 0` for
report-only behavior.

Output is tab-separated by default; `--format json` produces JSON Lines with
one object per finding, and `--format sarif` a single SARIF 2.1.0 document.

```sh
./secrets scan --format json /path/to/repository
./secrets scan --format sarif /path/to/repository > findings.sarif
```

Secrets and validation details are partially redacted by default; passing
`--redact=false` includes complete matched values in the output, so redirect
or store that output with care.

Useful scan options:

- `--workers`: concurrent blob readers; defaults to the current `GOMAXPROCS`
- `--max-blob-size`: largest blob to scan; defaults to 1 MiB
- `--attribute=false`: skip commit and path attribution
- `--validate`: check supported credentials against their providers
- `--cpuprofile`, `--memprofile`, and `--rule-timings`: write performance data

Run `./secrets scan --help` for every option. List the loaded detection rules
with:

```sh
./secrets rules
```

## Validation

`--validate` sends matched credentials to provider endpoints, so enable it
only where that outbound traffic is acceptable. Validation defaults to four
workers, a five-second request timeout, 100 requests per target, and five
requests per second across the scan.

The limits can be changed with `--validation-workers`, `--validate-timeout`,
`--validation-max-requests-per-target`, and
`--validation-requests-per-second`. A request cap or rate of 0 removes that
limit. `--validation-env-vars` allowlists environment variables that
validation rules may read.

Interrupting the command cancels blob processing and active validation work.
Validation status, reason, and metadata are included in TSV, JSON, and SARIF
output, with redaction applied unless `--redact=false` is set.

## Go package

Import `github.com/git-pkgs/secrets/scanner` to scan blob bytes directly:

```go
s, err := scanner.New(ctx, scanner.Options{})
if err != nil {
	return err
}
defer s.Close()

result, err := s.Scan(ctx, blobBytes, "config.yml")
if err != nil {
	return err
}
for _, finding := range result.Findings {
	fmt.Println(finding.RuleID, finding.StartLine)
}
```

Construct one scanner and share it across concurrent calls. Pass an empty path
when no repository path is available. A supplied path enables path-only rules
and exclusions; binary blobs can produce path-only findings. UTF-16 decoding
and the embedded or compiled prefilter are shared with the CLI.

The library scanner and CLI use Go's standard regexp engine.

Findings contain unredacted secrets. `Result.Scanned` reports whether text
passed the prefilter. The package applies no blob size limit, traverses no
history, and maintains no OID cache. Callers handle those steps and attribute
findings to commits and paths. Cache keys must account for paths when using
path-based rules or exclusions.

`ScanFS` walks an `fs.FS`, such as `os.DirFS(dir)`, and scans each regular
file with its slash-separated path. `FSOptions` sets the worker count and a
file size limit, and the visit callback is called for one file at a time.

Validation is disabled by default. Set `Options.Validation.Enabled` to enable
provider requests, with limits and timeouts in `Options.Validation`.
Validation results and request limits are shared across calls to the same
scanner. Canceling a call's context cancels that scan; canceling the context
passed to `New`, or calling `Close`, cancels all active scans.

## Scan coverage

Blobs larger than the 1 MiB default `--max-blob-size` are skipped, as is
binary content, though filename-only rules still run when path attribution is
enabled.

BOM-marked UTF-16LE and UTF-16BE text is decoded before scanning; UTF-8 and
unknown encodings are scanned as supplied. The summary's skipped count
combines size limits, binary classification, and prefilter rejection.

Path-based rules and exclusions require attribution: with
`--attribute=false`, output omits commit and path data, and those path checks
are skipped.

## Rule corpus

The checked-in rule corpus comes from Betterleaks; its source module,
version, and checksum are recorded in `betterleaks/corpus.json`. Update the
corpus and regenerate the embedded pattern databases with:

```sh
go run ./cmd/synccorpus -version <version>
go generate ./scanner
go generate -tags gohs ./scanner
```

The default build checks the embedded database against the loaded rule
configuration at startup and recompiles the patterns when they differ. The
summary then reports the `scan-compiled` engine instead of `scan-embedded`.

## Development

Run the default and race suites with:

```sh
go test ./...
go test -race ./...
```

The `gohs` suites require the native dependencies described in the build
section:

```sh
go test -tags gohs ./...
```

## License

[MIT](LICENSE).
