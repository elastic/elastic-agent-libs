// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build requirefips

// Package fipsscan provides helpers for auditing FIPS 140-3 compliance of Go
// binaries by scanning their dependency trees for forbidden (non-FIPS) imports.
// Only crypto/* stdlib packages are covered by Go's certified FIPS 140-3 module
// (GOFIPS140=v1.0.0); other crypto implementations are potential violations.
package fipsscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Non-FIPS crypto library prefixes. All are included in ForbiddenPkgs()
// and checked by Scan automatically. Use individual constants only when
// passing a subset via extraForbiddenPkgs.
const (
	// XCrypto covers golang.org/x/crypto, which is not part of Go's certified
	// FIPS 140-3 module (GOFIPS140=v1.0.0).
	XCrypto = "golang.org/x/crypto/"

	// JcmturnerAescts covers github.com/jcmturner/aescts (AES-CBC-CTS, own
	// AES block cipher implementation not using crypto/aes).
	JcmturnerAescts = "github.com/jcmturner/aescts/"

	// JcmturnerGofork covers github.com/jcmturner/gofork, a fork of stdlib
	// encoding/asn1 and crypto packages with non-FIPS modifications.
	JcmturnerGofork = "github.com/jcmturner/gofork/"

	// JcmturnerGokrb5 covers github.com/jcmturner/gokrb5 (Kerberos 5); pulls
	// in JcmturnerAescts and JcmturnerGofork.
	JcmturnerGokrb5 = "github.com/jcmturner/gokrb5/"

	// XdgGoPbkdf2 covers github.com/xdg-go/pbkdf2, a standalone PBKDF2
	// implementation independent of Go's crypto/pbkdf2.
	XdgGoPbkdf2 = "github.com/xdg-go/pbkdf2"

	// ProtonMailGoCrypto covers github.com/ProtonMail/go-crypto (OpenPGP);
	// implements its own OpenPGP cipher suite including non-FIPS algorithms.
	ProtonMailGoCrypto = "github.com/ProtonMail/go-crypto/"

	// CloudflareCircl covers github.com/cloudflare/circl; implements a wide
	// variety of primitives (SIDH, FourQ, Ristretto255, etc.) outside FIPS scope.
	CloudflareCircl = "github.com/cloudflare/circl/"

	// AzureGoNtlmssp covers github.com/Azure/go-ntlmssp; implements NTLM/SSPI
	// authentication which relies on MD4/MD5/DES — none FIPS-approved.
	AzureGoNtlmssp = "github.com/Azure/go-ntlmssp"

	// YoumarkPkcs8 covers github.com/youmark/pkcs8; handles PKCS#8 keys and
	// may negotiate non-FIPS ciphers (RC2, 3DES, SM4) depending on the key file.
	YoumarkPkcs8 = "github.com/youmark/pkcs8"

	// FilippioIO covers filippo.io/ packages (edwards25519, age, mlkem768,
	// etc.). None are part of a FIPS 140-3 certified module boundary, even
	// when they implement a FIPS-standardized algorithm (e.g. FIPS 203 ML-KEM).
	FilippioIO = "filippo.io/"
)

// Violation is a forbidden import discovered in the dependency tree.
type Violation struct {
	Binary   string // binary entry point; empty for library modules
	Importer string // package that directly imports the forbidden package
	Imported string // forbidden package being imported
}

// KnownViolation documents an accepted non-FIPS import for use in knownViolations maps.
//
// Both Importer and Imported support three forms:
//   - "" (empty): wildcard — matches anything in that position.
//     Importer "" matches any intermediate package; Imported "" matches any forbidden package.
//   - exact path: matches only that specific package.
//   - module-root prefix: "github.com/foo/bar" matches "github.com/foo/bar" itself
//     and any subpackage "github.com/foo/bar/baz".
//
// Use prefix or wildcard to collapse many per-subpackage entries into one. For example,
// {Imported: "github.com/jcmturner/gokrb5/v8"} matches violations from any gokrb5 subpackage.
type KnownViolation struct {
	Importer string
	Imported string
	Reason   string // why this violation is acceptable; shown in test output
}

var forbiddenPkgs = []string{
	XCrypto,
	JcmturnerAescts,
	JcmturnerGofork,
	JcmturnerGokrb5,
	XdgGoPbkdf2,
	ProtonMailGoCrypto,
	CloudflareCircl,
	AzureGoNtlmssp,
	YoumarkPkcs8,
	FilippioIO,
}

// ForbiddenPkgs returns a fresh copy of the baseline non-FIPS crypto library
// prefixes. Scan uses this automatically; pass extraForbiddenPkgs only for
// project-specific additions beyond this list.
func ForbiddenPkgs() []string {
	cp := make([]string, len(forbiddenPkgs))
	copy(cp, forbiddenPkgs)
	return cp
}

type goListPackage struct {
	ImportPath string
	Name       string
	Imports    []string
}

// moduleRoot walks up from the working directory to find the nearest go.mod
// and returns its containing directory. go test sets cwd to the test package
// directory, so relative patterns like ./... need to run from the module root.
func moduleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("finding module root: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("finding module root: go.mod not found starting from %s", dir)
		}
		dir = parent
	}
}

// goListPackages runs go list -json -deps -tags requirefips from the module root
// and decodes the output. Shared by scanBinaries and Scan.
func goListPackages(t testing.TB, patterns []string) []goListPackage {
	t.Helper()
	args := append([]string{"list", "-json", "-deps", "-tags", "requirefips"}, patterns...)
	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Dir = moduleRoot(t)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list failed: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list failed: %v", err)
	}
	var pkgs []goListPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("parsing go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// scanBinaries is the internal implementation shared by ScanBinaries and
// CheckModule. It runs a single go list pass over all patterns, attributes each
// violation to its binary entry point via BFS, and returns the binaries found.
// When no binaries are present (library module) it falls back to flat violation
// detection with no Binary set, so CheckModule works for both module types.
func scanBinaries(t testing.TB, patterns []string, skipBinaries []string, extraForbiddenPkgs []string) ([]Violation, map[string][]string, []string) {
	t.Helper()

	pkgs := goListPackages(t, patterns)

	forbidden := append(ForbiddenPkgs(), extraForbiddenPkgs...)

	skip := make(map[string]bool, len(skipBinaries))
	for _, s := range skipBinaries {
		skip[s] = true
	}

	importGraph := make(map[string][]string, len(pkgs))
	var mains []string

	for _, p := range pkgs {
		if p.Name == "main" && !skip[p.ImportPath] {
			mains = append(mains, p.ImportPath)
		}
		importGraph[p.ImportPath] = p.Imports
	}

	if len(mains) == 0 {
		return findViolations(importGraph, forbidden), importGraph, nil
	}

	// Per-binary BFS attribution so each violation carries the entry point
	// that pulls it in.
	seen := make(map[string]bool)
	var violations []Violation
	for _, bin := range mains {
		for pkg := range bfsReachable(bin, importGraph) {
			if isForbidden(pkg, forbidden) {
				continue
			}
			for _, imp := range importGraph[pkg] {
				if isForbidden(imp, forbidden) {
					if key := bin + "\x00" + pkg + "\x00" + imp; !seen[key] {
						seen[key] = true
						violations = append(violations, Violation{Binary: bin, Importer: pkg, Imported: imp})
					}
				}
			}
		}
	}
	return violations, importGraph, mains
}

// bfsReachable returns the set of all packages reachable from from (inclusive)
// via forward edges in importGraph.
func bfsReachable(from string, importGraph map[string][]string) map[string]bool {
	reachable := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		for _, dep := range importGraph[pkg] {
			if !reachable[dep] {
				reachable[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	return reachable
}

// findViolations returns all (Importer, Imported) pairs in importGraph where
// Importer is not itself forbidden but directly imports a forbidden package.
func findViolations(importGraph map[string][]string, forbidden []string) []Violation {
	var violations []Violation
	for pkg, imports := range importGraph {
		if isForbidden(pkg, forbidden) {
			continue
		}
		for _, imp := range imports {
			if isForbidden(imp, forbidden) {
				violations = append(violations, Violation{Importer: pkg, Imported: imp})
			}
		}
	}
	return violations
}

// ScanBinaries runs a single `go list -json -deps -tags requirefips` pass over
// all patterns, attributes each violation to its binary entry point
// (Violation.Binary), and returns all violations and the merged import graph.
// Binaries whose import path appears in skipBinaries are excluded from the scan.
// Calls t.Fatalf if no binaries are found or on subprocess/parse errors.
func ScanBinaries(t testing.TB, patterns []string, skipBinaries []string, extraForbiddenPkgs []string) ([]Violation, map[string][]string) {
	t.Helper()
	violations, importGraph, mains := scanBinaries(t, patterns, skipBinaries, extraForbiddenPkgs)
	if len(mains) == 0 {
		t.Fatalf("ScanBinaries: no package main found matching %v", patterns)
	}
	return violations, importGraph
}

// Scan runs `go list -json -deps -tags requirefips <pkg>` and returns all
// violations and the full import graph. Calls t.Fatalf on subprocess or parse
// errors.
func Scan(t testing.TB, pkg string, extraForbiddenPkgs []string) ([]Violation, map[string][]string) {
	t.Helper()
	pkgs := goListPackages(t, []string{pkg})
	forbidden := append(ForbiddenPkgs(), extraForbiddenPkgs...)
	importGraph := make(map[string][]string, len(pkgs))
	for _, p := range pkgs {
		importGraph[p.ImportPath] = p.Imports
	}
	return findViolations(importGraph, forbidden), importGraph
}

// matchesBinaryKey reports whether a binary key matches an actual binary import
// path. The key may be an exact import path, a module-root prefix, or "" which
// matches any binary.
func matchesBinaryKey(key, binary string) bool {
	if key == "" {
		return true
	}
	bare := strings.TrimRight(key, "/")
	return binary == bare || strings.HasPrefix(binary, bare+"/")
}

func isForbidden(pkg string, forbiddenPkgs []string) bool {
	for _, prefix := range forbiddenPkgs {
		bare := strings.TrimRight(prefix, "/")
		if pkg == bare || strings.HasPrefix(pkg, bare+"/") {
			return true
		}
	}
	return false
}

// ShortestChain returns the shortest path from `from` to `to` using forward
// edges in importGraph (package -> packages it imports). Returns nil if no path.
func ShortestChain(from, to string, importGraph map[string][]string) []string {
	if from == to {
		return []string{from}
	}

	type state struct {
		pkg  string
		path []string
	}

	visited := make(map[string]bool)
	visited[from] = true
	queue := []state{{pkg: from, path: []string{from}}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for _, next := range importGraph[cur.pkg] {
			if visited[next] {
				continue
			}
			newPath := make([]string, len(cur.path)+1)
			copy(newPath, cur.path)
			newPath[len(cur.path)] = next

			if next == to {
				return newPath
			}

			visited[next] = true
			queue = append(queue, state{pkg: next, path: newPath})
		}
	}

	return nil
}

// FormatChain joins a chain with indented " -> " separators for readable output:
//
//	pkg/a
//	      -> pkg/b
//	      -> pkg/c
func FormatChain(chain []string) string {
	if len(chain) == 0 {
		return ""
	}
	parts := make([]string, len(chain))
	parts[0] = chain[0]
	for i := 1; i < len(chain); i++ {
		parts[i] = "      -> " + chain[i]
	}
	return strings.Join(parts, "\n")
}

// CheckModule scans all packages and their transitive dependencies matching
// patterns and reports unknown violations or stale knownViolations entries via
// t.Errorf. Works for both binary and library modules.
//
// knownViolations is a two-level map:
//   - Outer key: binary entry-point import path, or "" to match all binaries.
//     May be a module-root prefix (e.g. "github.com/elastic/myagent") that
//     matches any binary whose import path starts with that prefix.
//   - Inner key: component — a package path or module-root prefix that must be
//     reachable from the binary AND able to reach the violating importer in the
//     import graph. Use "" to match any violation within that binary.
//
// A single violation can match multiple component keys simultaneously: if both
// "fbreceiver" and "azureauthextension" can transitively reach the same
// non-FIPS importer, listing the same (Importer, Imported) pair under both
// component keys causes both to be suppressed and neither to be flagged stale.
// This is the intended way to document violations shared by multiple components.
//
// For a violation like:
//
//	cmd/kafkareceiver
//	      -> otel-contrib/receiver/kafkareceiver
//	      -> otel-contrib/internal/kafka          ← Importer
//	      -> gokrb5/v8/client                     ← Imported (forbidden)
//
// Any of the following are valid component keys:
//
//	""                                    — matches any violation in this binary
//	"otel-contrib"                        — the external module root
//	"otel-contrib/receiver/kafkareceiver" — the specific receiver package
//	"otel-contrib/internal/kafka"         — the exact direct importer
//
// Stale detection: an entry is flagged stale when the binary was scanned, the
// component can still reach the importer, but the (Importer, Imported) pair is
// no longer a violation. Entries whose component is no longer reachable from the
// binary, or whose component can no longer reach the importer, are silently
// skipped (dependency removed or path broken).
//
// Binaries in skipBinaries are excluded from the scan and from stale detection.
func CheckModule(t testing.TB, patterns []string, skipBinaries []string, extraForbiddenPkgs []string, knownViolations map[string]map[string][]KnownViolation) {
	t.Helper()

	violations, importGraph, mains := scanBinaries(t, patterns, skipBinaries, extraForbiddenPkgs)

	// matched[binKey][compKey][i] tracks whether knownViolations[binKey][compKey][i] was hit.
	matched := make(map[string]map[string][]bool)
	for binKey, comps := range knownViolations {
		matched[binKey] = make(map[string][]bool, len(comps))
		for compKey, kvs := range comps {
			matched[binKey][compKey] = make([]bool, len(kvs))
		}
	}

	// Pre-compute reachable set per binary for stale detection.
	reachableFrom := make(map[string]map[string]bool, len(mains))
	for _, bin := range mains {
		reachableFrom[bin] = bfsReachable(bin, importGraph)
	}

	// Pre-compute which packages in importGraph match each component key
	// (exact path or module-root prefix). Used by componentCanReach.
	compPkgs := make(map[string][]string)
	for _, comps := range knownViolations {
		for compKey := range comps {
			if compKey == "" {
				continue
			}
			if _, seen := compPkgs[compKey]; seen {
				continue
			}
			prefix := compKey + "/"
			for pkg := range importGraph {
				if pkg == compKey || strings.HasPrefix(pkg, prefix) {
					compPkgs[compKey] = append(compPkgs[compKey], pkg)
				}
			}
		}
	}

	compReach := newReachabilityCache(importGraph)

	// componentCanReach reports whether the component identified by key can
	// reach importer via forward edges in the import graph. key "" is a wildcard.
	componentCanReach := func(key, importer string) bool {
		if key == "" {
			return true
		}
		for _, pkg := range compPkgs[key] {
			if compReach.from(pkg)[importer] {
				return true
			}
		}
		return false
	}

	// importerMatches reports whether kv.Importer matches the actual importer.
	//   - kv.Importer == "": wildcard, matches any importer.
	//   - exact path: must equal importer exactly.
	//   - prefix: "github.com/foo/bar" matches "github.com/foo/bar/baz".
	importerMatches := func(kv KnownViolation, importer string) bool {
		if kv.Importer == "" {
			return true
		}
		return kv.Importer == importer || strings.HasPrefix(importer, kv.Importer+"/")
	}

	// importedMatches reports whether kv.Imported matches the actual imported package.
	//   - kv.Imported == "": wildcard, matches any forbidden package.
	//   - exact path or prefix: trailing slash is stripped before matching so
	//     using an exported constant like XCrypto works correctly.
	importedMatches := func(kv KnownViolation, imported string) bool {
		if kv.Imported == "" {
			return true
		}
		bare := strings.TrimRight(kv.Imported, "/")
		return imported == bare || strings.HasPrefix(imported, bare+"/")
	}

	// componentCanReachImporter is the stale-detection fast path: returns false
	// when the component can provably no longer reach the importer (or any
	// subpackage of it), signalling a silent skip instead of a stale error.
	// When kv.Importer is empty the check is skipped (we can't narrow to a
	// specific importer, so let the matched flag decide).
	componentCanReachImporter := func(compKey string, kv KnownViolation) bool {
		if compKey == "" || kv.Importer == "" {
			return true
		}
		sub := kv.Importer + "/"
		for _, pkg := range compPkgs[compKey] {
			reachable := compReach.from(pkg)
			if reachable[kv.Importer] {
				return true
			}
			for rPkg := range reachable {
				if strings.HasPrefix(rPkg, sub) {
					return true
				}
			}
		}
		return false
	}

	// binKeysForBinary returns all keys in knownViolations that should be
	// consulted for a given binary import path: the exact path, any registered
	// key that is a module-root prefix of the binary, and always "".
	binKeysForBinary := func(binary string) []string {
		if binary == "" {
			return []string{""}
		}
		keys := []string{binary, ""}
		for key := range knownViolations {
			if key == "" || key == binary {
				continue
			}
			if matchesBinaryKey(key, binary) {
				keys = append(keys, key)
			}
		}
		return keys
	}

	// markKnown finds ALL known entries where the component can reach importer
	// and (Importer, Imported) matches. Marks each matched entry and returns the
	// full list so the caller can log reasons. A single violation can match
	// multiple component keys.
	markKnown := func(binary, importer, imported string) ([]KnownViolation, bool) {
		var results []KnownViolation
		for _, binKey := range binKeysForBinary(binary) {
			for compKey, kvs := range knownViolations[binKey] {
				if !componentCanReach(compKey, importer) {
					continue
				}
				for i, kv := range kvs {
					if importerMatches(kv, importer) && importedMatches(kv, imported) {
						matched[binKey][compKey][i] = true
						results = append(results, kv)
					}
				}
			}
		}
		return results, len(results) > 0
	}

	for _, v := range violations {
		var chain []string
		if v.Binary != "" {
			chain = ShortestChain(v.Binary, v.Importer, importGraph)
			if chain == nil {
				chain = []string{v.Importer}
			}
		} else {
			chain = []string{v.Importer}
		}
		displayChain := make([]string, len(chain)+1)
		copy(displayChain, chain)
		displayChain[len(chain)] = v.Imported

		if kvs, ok := markKnown(v.Binary, v.Importer, v.Imported); ok {
			for _, kv := range kvs {
				t.Logf("known violation (%s):\n%s\n      reason: %s", v.Imported, FormatChain(displayChain), kv.Reason)
			}
		} else {
			t.Errorf("NEW violation — add to knownViolations or remove the dependency:\n%s", FormatChain(displayChain))
		}
	}

	// binsForKey returns all scanned binaries whose import path matches a binary
	// key (exact or module-root prefix). Returns mains for the "" wildcard.
	binsForKey := func(key string) []string {
		if key == "" {
			return mains
		}
		var result []string
		for _, bin := range mains {
			if matchesBinaryKey(key, bin) {
				result = append(result, bin)
			}
		}
		return result
	}

	for binKey, comps := range matched {
		binsToCheck := binsForKey(binKey)
		// Skip entries whose binary key matched no scanned binary — avoids false
		// stale errors when CheckModule is called per-binary in subtests.
		if binKey != "" && len(binsToCheck) == 0 {
			continue
		}
		for compKey, hits := range comps {
			if compKey != "" {
				if len(binsToCheck) > 0 {
					// Binary mode: component must be reachable from at least one matching binary.
					if !isReachableFromAny(compKey, binsToCheck, reachableFrom) {
						continue
					}
				} else {
					// Library mode: no binary entry points. Check that the component
					// still exists somewhere in the import graph.
					if len(compPkgs[compKey]) == 0 {
						continue
					}
				}
			}
			for i, hit := range hits {
				if !hit {
					kv := knownViolations[binKey][compKey][i]
					// If the component can no longer reach the importer (or any
					// subpackage of it), the import path was broken — skip silently.
					if !componentCanReachImporter(compKey, kv) {
						continue
					}
					t.Errorf("stale knownViolations entry (no longer a violation — remove it): binary=%q component=%q importer=%q imported=%q", binKey, compKey, kv.Importer, kv.Imported)
				}
			}
		}
	}
}

// reachabilityCache lazily computes and caches the reachable-package set for
// any starting package. Shared across multiple componentCanReach calls so each
// BFS runs at most once per starting package.
type reachabilityCache struct {
	importGraph map[string][]string
	cache       map[string]map[string]bool
}

func newReachabilityCache(importGraph map[string][]string) *reachabilityCache {
	return &reachabilityCache{importGraph: importGraph, cache: make(map[string]map[string]bool)}
}

// from returns the full set of packages reachable from pkg (inclusive).
func (r *reachabilityCache) from(pkg string) map[string]bool {
	if cached, ok := r.cache[pkg]; ok {
		return cached
	}
	result := bfsReachable(pkg, r.importGraph)
	r.cache[pkg] = result
	return result
}

// isReachableFromAny reports whether key or any subpackage of key is reachable
// from at least one binary in bins.
func isReachableFromAny(key string, bins []string, reachableFrom map[string]map[string]bool) bool {
	prefix := key + "/"
	for _, bin := range bins {
		reachable := reachableFrom[bin]
		if reachable[key] {
			return true
		}
		for pkg := range reachable {
			if strings.HasPrefix(pkg, prefix) {
				return true
			}
		}
	}
	return false
}
