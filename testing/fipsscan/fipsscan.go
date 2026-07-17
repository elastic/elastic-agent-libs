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
	"os/exec"
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

// scanBinaries is the internal implementation shared by ScanBinaries and
// CheckModule. It runs a single go list pass over all patterns, attributes each
// violation to its binary entry point via BFS, and returns the binaries found.
// When no binaries are present (library module) it falls back to flat violation
// detection with no Binary set, so CheckModule works for both module types.
func scanBinaries(t testing.TB, patterns []string, skipBinaries []string, extraForbiddenPkgs []string) ([]Violation, map[string][]string, []string) {
	t.Helper()

	args := append([]string{"list", "-json", "-deps", "-tags", "requirefips"}, patterns...)
	cmd := exec.CommandContext(t.Context(), "go", args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list failed: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list failed: %v", err)
	}

	forbidden := append(ForbiddenPkgs(), extraForbiddenPkgs...)

	skip := make(map[string]bool, len(skipBinaries))
	for _, s := range skipBinaries {
		skip[s] = true
	}

	importGraph := make(map[string][]string)
	var mains []string

	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("parsing go list output: %v", err)
		}
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

	cmd := exec.CommandContext(t.Context(), "go", "list", "-json", "-deps", "-tags", "requirefips", pkg)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list failed: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list failed: %v", err)
	}

	forbidden := append(ForbiddenPkgs(), extraForbiddenPkgs...)
	importGraph := make(map[string][]string)

	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("parsing go list output: %v", err)
		}
		importGraph[p.ImportPath] = p.Imports
	}

	return findViolations(importGraph, forbidden), importGraph
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
// t.Errorf. Works for both binary and library modules. The map key is the
// binary entry point path; use "" for violations that apply to all binaries or
// to library modules. Binaries in skipBinaries are excluded from the scan and
// from stale detection. Stale detection only covers binaries found in this scan,
// so per-binary subtest calls work correctly with per-binary map keys.
func CheckModule(t testing.TB, patterns []string, skipBinaries []string, extraForbiddenPkgs []string, knownViolations map[string][]KnownViolation) {
	t.Helper()

	violations, importGraph, mains := scanBinaries(t, patterns, skipBinaries, extraForbiddenPkgs)

	// matched[binary][i] tracks whether knownViolations[binary][i] was hit.
	matched := make(map[string][]bool)
	for bin, kvs := range knownViolations {
		matched[bin] = make([]bool, len(kvs))
	}

	findKnown := func(binary, importer, imported string) (KnownViolation, bool) {
		bins := []string{binary, ""}
		if binary == "" {
			bins = []string{""}
		}
		for _, bin := range bins {
			for i, kv := range knownViolations[bin] {
				if kv.Importer == importer && kv.Imported == imported {
					matched[bin][i] = true
					return kv, true
				}
			}
		}
		return KnownViolation{}, false
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

		if kv, ok := findKnown(v.Binary, v.Importer, v.Imported); ok {
			t.Logf("known violation (%s):\n%s\n      reason: %s", v.Imported, FormatChain(displayChain), kv.Reason)
		} else {
			t.Errorf("NEW violation — add to knownViolations or remove the dependency:\n%s", FormatChain(displayChain))
		}
	}

	// Only check staleness for binaries found in this scan — avoids false
	// stale errors when CheckModule is called per-binary in subtests.
	scanned := make(map[string]bool, len(mains)+1)
	for _, bin := range mains {
		scanned[bin] = true
	}
	scanned[""] = true

	for bin, hits := range matched {
		if !scanned[bin] {
			continue
		}
		for i, hit := range hits {
			if !hit {
				kv := knownViolations[bin][i]
				t.Errorf("stale knownViolations entry (no longer a violation — remove it): binary=%q importer=%q imported=%q", bin, kv.Importer, kv.Imported)
			}
		}
	}
}
