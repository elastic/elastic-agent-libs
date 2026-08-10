# fipsscan

`fipsscan` is a Go testing helper for auditing import-policy compliance of Go modules. It scans a module's dependency tree for imports of forbidden packages and reports violations against a caller-supplied allowlist.

The package ships with **no default forbidden-package list** — that is the caller's responsibility. This makes it reusable for any import-policy audit, not just FIPS. The package itself carries no build constraints; the `//go:build requirefips` tag in the example below is a convention for the *caller's* test file.

## Naming convention

> **Recommendation:** use the filename `fips_compliance_test.go` and the test function `TestFIPSCompliance` in every module that adopts this package.

Consistent naming makes it easy to audit coverage across the Elastic ecosystem:

```
# find all modules that have a FIPS compliance test
grep -rl 'TestFIPSCompliance' .

# run only the FIPS compliance test in a single module
go test -tags requirefips -run TestFIPSCompliance ./...
```

Note: `./...` stays within one Go module. In a multi-module workspace you need `go work` or a loop over module roots.

## Quick start

For most modules, `CheckModule` is all you need. Create `fips_compliance_test.go`:

```go
//go:build requirefips

package fips_test

import (
    "testing"

    "github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

var forbiddenPkgs = []string{
    "golang.org/x/crypto/",
    "github.com/jcmturner/gokrb5/",
    "github.com/jcmturner/aescts/",
    "github.com/jcmturner/gofork/",
    "github.com/xdg-go/pbkdf2",
    "github.com/ProtonMail/go-crypto/",
    "github.com/cloudflare/circl/",
    "github.com/Azure/go-ntlmssp",
    "github.com/youmark/pkcs8",
}

var skipBinaries = []string{
    // "github.com/elastic/mymodule/dev-tools/cmd/tool",
}

func TestFIPSCompliance(t *testing.T) {
    fipsscan.CheckModule(t,
        []string{"./..."},
        skipBinaries,
        forbiddenPkgs,
        []string{"requirefips"},
        map[string]map[string][]fipsscan.KnownViolation{
            // See "Known-violations map" below.
            "github.com/elastic/mymodule": {
                "github.com/elastic/gokrb5/v8": {
                    {Imported: "github.com/jcmturner/aescts", Reason: "elastic/gokrb5 fork: AES-CBC-CTS key derivation"},
                    {Imported: "golang.org/x/crypto/md4",     Reason: "Kerberos RC4-HMAC; no FIPS-approved substitute"},
                },
            },
        },
    )
}
```

Run with:

```
go test -tags requirefips ./...
```

`go list` runs from the module root (the nearest `go.mod` above the test file), so `"./..."` covers the entire module regardless of where the test lives. On a cold module cache `go list` may download dependencies.

## How the scan works

`CheckModule` runs `go list -deps` once and checks every package in the dependency graph in two passes:

**Binary scope** — packages pulled in by each non-skipped `package main`. Violations carry the binary's import path in `Violation.Binary`.

**Flat scope** — packages not pulled in by any binary, i.e. library-only code. Violations carry `Binary=""` and `Importer` set to the package that directly imports the forbidden one.

Both passes always run. A pure-library module (no `package main`) is fully covered by the flat scope.

## Known-violations map

The `known` argument to `CheckModule` is `map[binary]map[component][]KnownViolation`.

### Binary key (outer map)

Scopes an entry to a specific binary (or set of binaries via prefix). An empty key `""` covers all violations — binary-scope and flat-scope alike — so use it with care.

| Key | Matches |
|---|---|
| `"github.com/elastic/agent/cmd/otelcol"` | that binary and any binary whose path starts with it |
| `"github.com/elastic/agent"` | any binary whose import path starts with this prefix |
| `""` | every violation in the module — binary-scope and flat-scope alike (wildcard) |

A non-`""` key that matches no scanned binary is reported as an error — it is a typo or a stale entry. Entries under an unknown key are skipped (not reported stale); fix the key path to see their stale status.

### Component key (inner map)

Identifies which library is responsible for pulling in the forbidden package. The entry matches a violation only when that library lies on the import chain from the binary to the forbidden package.

| Key | Meaning |
|---|---|
| `"github.com/twmb/franz-go"` | franz-go (or a sub-package) is responsible for the forbidden import |
| `"github.com/elastic/gokrb5/v8/client"` | this specific sub-package is responsible |
| `""` | no constraint — any import chain from binary to forbidden matches |

The component key makes entries self-maintaining: when the responsible library stops importing the forbidden package, the entry goes stale automatically, even if the forbidden package is still reachable via a different route.

A non-`""` component key never matches flat-scope violations — use `""` as the component key for library-only entries.

### KnownViolation fields

| Field | Description |
|---|---|
| `Imported` | prefix-matched against the forbidden package; `""` matches any forbidden package |
| `Reason` | free-text explanation for documentation; never printed or validated |

### Stale detection

`CheckModule` reports a stale entry when an allowlist entry no longer matches any actual violation. This catches:

- A dependency that was updated to remove the forbidden import.
- A component library that was removed from the module.
- A binary key that was renamed or removed.

The `""` binary key is always checked for stale entries. A non-`""` key is only checked when it matches at least one scanned binary; if it matches none, a separate "unknown binary key" error fires instead.

## skipBinaries

`skipBinaries` accepts import paths and module-root prefixes (same matching rules as binary keys). A skip entry that matches no discovered binary is reported as an error.

**Important:** skipping a binary removes it from the binary-scope scan. Any package used exclusively by the skipped binary re-appears as a flat-scope violation (`Binary=""`), which cannot be keyed by binary path. Dev-tool binaries whose violations are already documented under a binary key will produce fresh "unknown binary key" errors when added to `skipBinaries`; remove their allowlist entries at the same time.

## Prefix matching

The same matching rule applies everywhere — `forbiddenPkgs`, `skipBinaries`, binary keys, component keys, and `KnownViolation.Imported`:

- Trailing slashes are stripped from the **pattern** before matching (not from the path).
- `""` (or `"/"` after stripping) is a wildcard that matches anything.
- Otherwise a match requires `path == pattern` or `path` starts with `pattern + "/"`, so `"github.com/foo"` matches `"github.com/foo/bar"` but not `"github.com/foobar"`.

## Bootstrapping the known-violations map

1. Call `CheckModule` with an empty map (`map[string]map[string][]fipsscan.KnownViolation{}`).
2. Every `NEW violation` is printed with its full import chain. Binary-scope violations show the full path from the binary to the forbidden package:

```
fips_compliance_test.go:XX: NEW violation:
    github.com/elastic/agent/internal/edot/cmd/otelcol
          -> github.com/open-telemetry/otelcol-contrib/receiver/kafkareceiver
          -> github.com/twmb/franz-go/pkg/sasl/scram
          -> golang.org/x/crypto/pbkdf2
```

Flat-scope violations show only the direct importer and the forbidden package:

```
fips_compliance_test.go:XX: NEW violation:
    github.com/elastic/elastic-agent-libs/transport/tlscommon
          -> golang.org/x/crypto/md4
```

3. Fill in the map from the chain (binary-scope example):

| Map field | From the chain |
|---|---|
| binary key | first line: `"github.com/elastic/agent/internal/edot/cmd/otelcol"` |
| component key | any library between binary and forbidden, or its module-root prefix: `"github.com/twmb/franz-go"` |
| `Imported` | last line (or a prefix of it): `"golang.org/x/crypto/pbkdf2"` |
| `Reason` | the receiver visible in the chain: `"kafkareceiver: Kafka SCRAM SASL key derivation"` |

4. Re-run the test. Repeat until clean.

Binary-scope violations are deduplicated per binary/forbidden-package pair — one error showing the shortest chain. Flat-scope violations are deduplicated per importer/forbidden-package pair. Fixing the printed chain may surface another chain for the same pair; repeat until the violation disappears.

For flat-scope violations, use `""` as both the binary key and the component key. Note that a `""` binary key also covers binary-scope violations.

## Coverage limits

`go list` runs without `-test`, so test-only imports are not scanned. Build constraints are evaluated for the current `GOOS`/`GOARCH`, so platform-specific imports (e.g. a `_windows.go` file) are not scanned on Linux CI.

## API reference

### CheckModule

```go
func CheckModule(
    t             testing.TB,
    patterns      []string,                        // passed to go list, e.g. []string{"./..."}
    skipBinaries  []string,                        // binary import paths/prefixes to exclude
    forbiddenPkgs []string,                        // import-path prefixes to flag as violations
    tags          []string,                        // build tags for go list (e.g. []string{"requirefips"})
    known         map[string]map[string][]KnownViolation,
)
```

Fatals (`t.Fatalf`) on empty `patterns`, empty `forbiddenPkgs`, `go list` failure, or missing `go.mod`. Reports via `t.Errorf`:

- `NEW violation` — forbidden import with no matching known entry
- `stale entry in knownViolations` — known entry whose violation no longer exists
- `knownViolations binary key ... matches no scanned binary` — non-`""` binary key matching no scanned binary
- `skipBinaries entry ... matches no discovered binary` — skip entry matching no discovered binary

### Scan

```go
func Scan(
    t             testing.TB,
    patterns      []string,
    skipBinaries  []string,
    forbiddenPkgs []string,
    tags          []string,
) []Violation
```

Returns raw violations without consulting an allowlist. Useful for bootstrapping or custom reporting.

### ShortestChain / FormatChain

```go
func ShortestChain(from, to string, graph map[string][]string) []string
func FormatChain(chain []string) string
```

Graph-walking helpers available for callers that build their own import graph.

### Types

```go
type Violation struct {
    Binary   string // binary import path; "" for flat-scope violations
    Importer string // direct importer of the forbidden package; set only for flat-scope violations
    Imported string // the forbidden package
}

type KnownViolation struct {
    Imported string // prefix-matched against Violation.Imported; "" matches anything
    Reason   string // why this violation is accepted; documentation only, never printed
}
```

`Violation.Importer` is empty for binary-scope violations — the full chain is reconstructed via `ShortestChain` internally.
