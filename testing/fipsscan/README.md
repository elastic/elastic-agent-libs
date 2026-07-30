# fipsscan

`fipsscan` is a Go testing helper for auditing import-policy compliance of Go binaries. It scans a module's dependency tree for imports of forbidden packages and reports violations against a caller-supplied allowlist.

The package carries **no build constraints** and ships **no default forbidden-package list** — both are the caller's responsibility. This makes it reusable for any import-policy audit, not just FIPS.

## Naming convention

> **Recommendation:** use the filename `fips_compliance_test.go` and the test function `TestFIPSCompliance` in every module that adopts this package.

Consistent naming makes it easy to audit coverage across the Elastic ecosystem:

```
# find all modules that have a FIPS compliance test
grep -rl 'TestFIPSCompliance' .

# run only the FIPS compliance test across all modules in a monorepo
go test -tags requirefips -run TestFIPSCompliance ./...
```

It also makes CI configuration uniform: a single `-run TestFIPSCompliance` flag works everywhere without per-module customisation.

## Quick start

For most modules, `CheckModule` is all you need. Create `fips_compliance_test.go`:

```go
//go:build requirefips

package fips_test

import (
    "testing"

    "github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

// forbiddenPkgs lists import-path prefixes that are not permitted in this
// module's dependency tree. Adjust to match your project's FIPS policy.
var forbiddenPkgs = []string{
    "golang.org/x/crypto/",
    "github.com/jcmturner/gokrb5/",
    "github.com/cloudflare/circl/",
}

// skipBinaries lists non-shipped binaries excluded from the FIPS scan.
var skipBinaries = []string{
    // "github.com/elastic/myagent/dev-tools/cmd/sometool",
}

func TestFIPSCompliance(t *testing.T) {
    fipsscan.CheckModule(t,
        []string{"./..."},
        skipBinaries,
        forbiddenPkgs,
        []string{"requirefips"},
        map[string]map[string][]fipsscan.KnownViolation{
            // Outer key: binary entry-point import path, a module-root prefix
            //   that matches any binary under it, or "" for all binaries.
            //   E.g. "github.com/elastic/myagent" matches both
            //   "github.com/elastic/myagent/cmd/agent" and
            //   "github.com/elastic/myagent/cmd/other".
            // Inner key: component — a package path or module-root prefix that
            //   must be reachable from the binary AND able to reach the importer.
            //   Use a specific component (e.g. "receiver/kafkareceiver") to
            //   document which component owns the violation. List the same
            //   (Importer, Imported) under multiple components when several are
            //   affected by the same shared library.
            //   Use "" to match any violation within that binary.
            "github.com/elastic/myagent": {
                // Importer is optional: "" matches any package inside the component.
                // Imported supports module-root prefixes (trailing slash stripped automatically).
                "github.com/elastic/gokrb5/v8": {
                    {Imported: "github.com/jcmturner/aescts", Reason: "Elastic gokrb5 fork depends on jcmturner aescts for AES-CBC-CTS"},
                    {Imported: "golang.org/x/crypto/md4",     Reason: "Kerberos RC4-HMAC requires MD4; no FIPS-approved substitute"},
                },
                "github.com/twmb/franz-go": {
                    {Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified"},
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

`CheckModule` scans all packages and their transitive dependencies — binaries and libraries alike — so it works the same way regardless of module type.

## Bootstrapping the known-violations map

1. Call `CheckModule` with an empty map (`map[string]map[string][]fipsscan.KnownViolation{}`).
2. The test output lists every `NEW violation` with its full import chain, e.g.:
   ```
   cmd/kafkareceiver
         -> otel-contrib/receiver/kafkareceiver
         -> otel-contrib/internal/kafka          ← Importer
         -> gokrb5/v8/client                     ← Imported (forbidden)
   ```
3. Choose a component key — any package or prefix in the chain from the binary down to the Importer (not the forbidden package itself):
   | Component key | Meaning |
   |---|---|
   | `""` | matches any chain in this binary |
   | `"cmd/kafkareceiver"` | binary-level — don't need to know which package does the import |
   | `"otel-contrib"` | external module root — groups all violations from that module |
   | `"otel-contrib/receiver/kafkareceiver"` | specific receiver package |
   | `"otel-contrib/internal/kafka"` | exact direct importer |
4. Add a `Reason` explaining why the dependency cannot be replaced.
5. From that point on CI enforces the contract automatically.

## Advanced usage

`CheckModule` covers most cases. Use the lower-level functions when you need to build a custom reporting pipeline:

```go
// all packages in the module (Binary not set on violations)
violations, importGraph := fipsscan.Scan(t, "./...", forbiddenPkgs, []string{"requirefips"})

// only package main entry points (fatals if none found; Binary is set on each violation)
violations, importGraph := fipsscan.ScanBinaries(t, []string{"./cmd/agent", "./cmd/other"}, nil, forbiddenPkgs, []string{"requirefips"})

for _, v := range violations {
    chain := fipsscan.ShortestChain(v.Binary, v.Importer, importGraph)
    fmt.Println(fipsscan.FormatChain(append(chain, v.Imported)))
}
```

## API reference

```
CheckModule(t, patterns, skipBinaries, forbiddenPkgs, tags, knownViolations)
    Scans all packages matching patterns and their transitive dependencies.
    skipBinaries lists binary import paths to exclude (dev tools, scripts,
    non-shipped assets). forbiddenPkgs is the complete list of import-path
    prefixes to flag as violations — the caller owns this list entirely.
    tags is the list of build tags passed to go list (e.g. []string{"requirefips"});
    pass nil or an empty slice for no tags.
    knownViolations is map[binary]map[component][]KnownViolation:
      - outer key: binary entry-point path, a module-root prefix (matches any
        binary whose import path starts with it), or "" for all binaries
      - inner key: component — a package path or module-root prefix that must
        be reachable from the binary AND able to reach the violating importer;
        "" matches any violation within that binary
    A single violation can match multiple component keys simultaneously. List
    the same (Importer, Imported) pair under each component that transitively
    imports the forbidden package — all matched entries are suppressed, none
    are flagged stale as long as the violation persists.
    Stale detection: an entry is flagged stale when the binary was scanned,
    the component can still reach the importer, but the (Importer, Imported)
    pair is no longer a violation. Entries whose component is no longer
    reachable from the binary, or whose component can no longer reach the
    importer, are silently skipped. t.Errorf on new violations or stale entries.

Scan(t, pkg, forbiddenPkgs, tags)
    Scans pkg and its full dependency tree. Returns ([]Violation, importGraph).
    Binary is not set on violations.

ScanBinaries(t, patterns, skipBinaries, forbiddenPkgs, tags)
    Discovers all package main entries matching patterns, scans the combined
    dependency tree in one go list pass. skipBinaries lists binary import
    paths to exclude. Sets Binary on each violation. Fatals if no binaries
    are found.

ShortestChain(from, to, importGraph) []string
    BFS shortest path through the import graph. Useful for building custom
    violation reporters.

FormatChain(chain []string) string
    Formats an import chain for human-readable output.
```
