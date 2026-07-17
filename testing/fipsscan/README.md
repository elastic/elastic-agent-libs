# fipsscan

`fipsscan` is a Go testing helper for auditing FIPS 140-3 compliance. It scans a package's dependency tree for imports of known non-FIPS crypto libraries and reports violations.

The package is guarded by the `requirefips` build tag so it compiles — and incurs zero overhead — only in FIPS-focused test runs.

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

// skipBinaries lists non-shipped binaries excluded from the FIPS scan.
var skipBinaries = []string{
    // "github.com/elastic/myagent/dev-tools/cmd/sometool",
}

func TestFIPSCompliance(t *testing.T) {
    fipsscan.CheckModule(t,
        []string{"./..."},
        skipBinaries,
        nil, // project-specific extra forbidden pkgs; nil for the default set
        map[string]map[string][]fipsscan.KnownViolation{
            // Outer key: binary entry-point path, or "" for all binaries.
            // Inner key: component — any package path or module prefix that
            //   must appear in the BFS chain from the binary to the importer.
            //   Use a module root (e.g. "github.com/twmb/franz-go") to group
            //   all subpackage violations under one entry, making it clear
            //   which library introduces the violation.
            //   Use "" to match any chain within that binary.
            "github.com/elastic/myagent/cmd/agent": {
                "github.com/elastic/gokrb5/v8": {
                    {
                        Importer: "github.com/elastic/gokrb5/v8/crypto/rfc3962",
                        Imported: "github.com/jcmturner/aescts/v2",
                        Reason:   "Elastic gokrb5 fork depends on jcmturner aescts for AES-CBC-CTS",
                    },
                },
                "github.com/twmb/franz-go": {
                    {
                        Importer: "github.com/twmb/franz-go/pkg/sasl/scram",
                        Imported: "golang.org/x/crypto/pbkdf2",
                        Reason:   "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified",
                    },
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
2. The test output lists every violation with its full import chain.
3. Group violations by the module root of the importer (e.g. `"github.com/twmb/franz-go"`) to make it clear which library introduces each violation.
4. Add a `Reason` explaining why the dependency cannot be replaced.
5. From that point on CI enforces the contract automatically.

## Advanced usage

`CheckModule` covers most cases. Use the lower-level functions when you need to build a custom reporting pipeline:

```go
// all packages in the module (Binary not set on violations)
violations, importGraph := fipsscan.Scan(t, "./...", nil)

// only package main entry points (fatals if none found; Binary is set on each violation)
violations, importGraph := fipsscan.ScanBinaries(t, []string{"./cmd/agent", "./cmd/other"}, nil)

for _, v := range violations {
    chain := fipsscan.ShortestChain(v.Binary, v.Importer, importGraph)
    fmt.Println(fipsscan.FormatChain(append(chain, v.Imported)))
}
```

## What is checked

All functions check against `ForbiddenPkgs()` by default — a curated list of third-party crypto libraries that are not part of any FIPS 140-3 certified module boundary:

| Constant | Module prefix | Reason |
|---|---|---|
| `XCrypto` | `golang.org/x/crypto/` | Not in Go's GOFIPS140 certified module |
| `JcmturnerAescts` | `github.com/jcmturner/aescts/` | Own AES block cipher, not `crypto/aes` |
| `JcmturnerGofork` | `github.com/jcmturner/gofork/` | Fork of stdlib with non-FIPS modifications |
| `JcmturnerGokrb5` | `github.com/jcmturner/gokrb5/` | Kerberos 5; pulls in the two above |
| `XdgGoPbkdf2` | `github.com/xdg-go/pbkdf2` | Standalone PBKDF2, not `crypto/pbkdf2` |
| `ProtonMailGoCrypto` | `github.com/ProtonMail/go-crypto/` | OpenPGP with non-FIPS algorithms |
| `CloudflareCircl` | `github.com/cloudflare/circl/` | SIDH, FourQ, Ristretto255, etc. |
| `AzureGoNtlmssp` | `github.com/Azure/go-ntlmssp` | NTLM/SSPI — uses MD4/MD5/DES |
| `YoumarkPkcs8` | `github.com/youmark/pkcs8` | May negotiate RC2/3DES/SM4 |
| `FilippioIO` | `filippo.io/` | edwards25519, age, etc. (outside certified boundary even when implementing a FIPS-standardized algorithm) |

Pass additional prefixes via `extraForbiddenPkgs` for project-specific libraries not in this list.

**Deferred — `github.com/go-jose/`:** go-jose wraps stdlib `crypto/aes`, `crypto/rsa`, and `crypto/ecdsa` rather than implementing its own primitives, and its SHA-1 usage in RSA-OAEP is permitted under FIPS for key transport (NIST SP 800-131A). It is not in the baseline list to avoid false positives for common JWT/JWE usage. Projects that want stricter coverage can add it via `extraForbiddenPkgs` and manually review each hit.

## API reference

```
CheckModule(t, patterns, skipBinaries, extraForbiddenPkgs, knownViolations)
    Scans all packages matching patterns and their transitive dependencies.
    skipBinaries lists binary import paths to exclude (dev tools, scripts,
    non-shipped assets). knownViolations is map[binary]map[component][]KnownViolation:
      - outer key: binary entry-point path, or "" for all binaries
      - inner key: component prefix that must appear in the BFS chain from
        the binary to the importer; "" matches any chain
    Stale detection: entries are flagged stale when the binary was scanned and
    the component is reachable but the (Importer, Imported) pair is no longer
    a violation. If the component is no longer reachable, its entries are
    silently skipped. t.Errorf on new violations or stale entries.

Scan(t, pkg, extraForbiddenPkgs)
    Scans pkg and its full dependency tree. Returns ([]Violation, importGraph).
    Binary is not set on violations.

ScanBinaries(t, patterns, skipBinaries, extraForbiddenPkgs)
    Discovers all package main entries matching patterns, scans the combined
    dependency tree in one go list pass. skipBinaries lists binary import
    paths to exclude. Sets Binary on each violation. Fatals if no binaries
    are found.

ForbiddenPkgs() []string
    Returns a fresh copy of the baseline forbidden-prefix list.

ShortestChain(from, to, importGraph) []string
    BFS shortest path through the import graph. Useful for building custom
    violation reporters.

FormatChain(chain []string) string
    Formats an import chain for human-readable output.
```
