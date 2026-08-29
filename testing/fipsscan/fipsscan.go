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

// Package fipsscan provides helpers for auditing import-policy compliance of Go
// binaries by scanning their dependency trees for forbidden imports.
// The package is policy-agnostic: callers supply the forbidden-package prefixes
// and the known-violations allowlist.
package fipsscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Violation is a forbidden import found in the dependency graph.
type Violation struct {
	Binary   string // entry-point binary import path; "" for library-scope violations (flat scan)
	Importer string // the package directly importing the forbidden one; set for flat-scan violations
	Imported string // the forbidden package
}

// KnownViolation documents one accepted violation for a specific binary and component.
//
//	Imported: prefix-matched against the forbidden package; "" matches anything.
//	Reason:   why this violation is accepted; documentation only, never printed.
type KnownViolation struct {
	Imported string
	Reason   string
}

// CheckModule scans all packages matching patterns and reports via t.Errorf:
//
//   - NEW violation: a forbidden import with no matching knownViolations entry.
//   - stale entry:   a knownViolations entry whose violation no longer exists.
//   - unknown key:   a non-"" binary key that matches no scanned binary.
//
// known is map[binary]map[component][]KnownViolation:
//
//	binary key    — full import path of a package main, or "" for library scope.
//	                "" is always active. Non-"" keys that match no scanned binary
//	                are reported as errors.
//	component key — full import path prefix of a package that must lie on the
//	                path from the binary to the forbidden package. "" skips this
//	                check (any path from binary to forbidden is covered).
//
// Matching is by path prefix everywhere; trailing slashes in patterns are ignored.
//
// Both binary and flat scopes always run:
//
//	Binary scope: every package transitively imported by a non-skipped package main.
//	Flat scope:   all packages not reachable from any binary (library packages).
//
// Violations from the flat scope carry Binary="".
func CheckModule(t testing.TB, patterns []string, skipBinaries []string, forbiddenPkgs []string, tags []string, known map[string]map[string][]KnownViolation) {
	t.Helper()
	violations, graph, scannedBinaries := scan(t, patterns, skipBinaries, forbiddenPkgs, tags)
	checkViolations(t, violations, graph, scannedBinaries, known)
}

// Scan returns raw violations without consulting an allowlist.
// Useful for bootstrapping a new allowlist or custom reporting.
func Scan(t testing.TB, patterns []string, skipBinaries []string, forbiddenPkgs []string, tags []string) []Violation {
	t.Helper()
	violations, _, _ := scan(t, patterns, skipBinaries, forbiddenPkgs, tags)
	return violations
}

// scan returns scanned binaries with skipBinaries already filtered out.
func scan(t testing.TB, patterns []string, skipBinaries []string, forbiddenPkgs []string, tags []string) ([]Violation, map[string][]string, []string) {
	t.Helper()
	if len(patterns) == 0 {
		t.Fatalf("fipsscan: patterns must not be empty")
	}
	if len(forbiddenPkgs) == 0 {
		t.Fatalf("fipsscan: forbiddenPkgs must not be empty")
	}

	graph, allMains := goListPackages(t, moduleRoot(t), patterns, tags)
	validateSkipBinaries(t, skipBinaries, allMains)

	var scannedBinaries []string
	for _, m := range allMains {
		if !isSkipped(m, skipBinaries) {
			scannedBinaries = append(scannedBinaries, m)
		}
	}

	violations, unionReach := scanBinaryViolations(graph, scannedBinaries, forbiddenPkgs)
	violations = append(violations, scanFlatViolations(graph, unionReach, forbiddenPkgs)...)

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Binary != violations[j].Binary {
			return violations[i].Binary < violations[j].Binary
		}
		if violations[i].Importer != violations[j].Importer {
			return violations[i].Importer < violations[j].Importer
		}
		return violations[i].Imported < violations[j].Imported
	})
	return violations, graph, scannedBinaries
}

type goListPackage struct {
	ImportPath string
	Name       string
	Imports    []string
}

func goListPackages(t testing.TB, dir string, patterns []string, tags []string) (map[string][]string, []string) {
	t.Helper()
	// Field filtering keeps the decoded output small on large dependency trees.
	args := []string{"list", "-json=ImportPath,Name,Imports", "-deps"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, patterns...)

	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list failed: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list failed: %v", err)
	}

	graph := make(map[string][]string)
	var mains []string
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("parsing go list output: %v", err)
		}
		graph[p.ImportPath] = p.Imports
		if p.Name == "main" {
			mains = append(mains, p.ImportPath)
		}
	}
	sort.Strings(mains)
	return graph, mains
}

// go test sets cwd to the test package directory, so relative patterns like
// ./... need to run from the module root.
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
			return ""
		}
		dir = parent
	}
}

func isSkipped(binary string, skipBinaries []string) bool {
	for _, s := range skipBinaries {
		if pathMatches(s, binary) {
			return true
		}
	}
	return false
}

func checkViolations(t testing.TB, violations []Violation, graph map[string][]string, scannedBinaries []string, known map[string]map[string][]KnownViolation) {
	t.Helper()

	// reach memoizes bfsReachable: the same binary or component root is queried
	// once per violation, so cache results to avoid redundant graph walks.
	reachCache := make(map[string]map[string]bool)
	reach := func(pkg string) map[string]bool {
		if r, ok := reachCache[pkg]; ok {
			return r
		}
		r := bfsReachable(pkg, graph)
		reachCache[pkg] = r
		return r
	}

	// Pre-resolve each non-empty component key to the concrete packages it
	// matches. componentOnPath would otherwise scan the full graph on every
	// (violation, component) pair.
	componentPkgs := make(map[string][]string)
	for _, comps := range known {
		for ck := range comps {
			if ck == "" {
				continue
			}
			if _, done := componentPkgs[ck]; done {
				continue
			}
			var pkgs []string
			for pkg := range graph {
				if pathMatches(ck, pkg) {
					pkgs = append(pkgs, pkg)
				}
			}
			sort.Strings(pkgs)
			componentPkgs[ck] = pkgs
		}
	}

	// entryKey identifies one KnownViolation by its position in the nested map.
	// The index is needed because each entry goes stale independently: a wildcard
	// "" Imported entry matches many violations but is stale only when none do.
	type entryKey struct {
		bk, ck string
		i      int
	}
	matchedEntries := make(map[entryKey]bool)

	for _, v := range violations {
		matched := false
		for bk, comps := range known {
			if !pathMatches(bk, v.Binary) {
				continue
			}
			for ck, kvs := range comps {
				if !componentOnPath(v.Binary, ck, v.Imported, componentPkgs[ck], reach) {
					continue
				}
				for i, kv := range kvs {
					if pathMatches(kv.Imported, v.Imported) {
						matchedEntries[entryKey{bk, ck, i}] = true
						matched = true
					}
				}
			}
		}
		if matched {
			continue
		}
		// ShortestChain returns nil when Binary=="" (flat-scope violation) or
		// the binary is absent from the graph; fall back to a minimal chain so
		// the error message is still useful.
		chain := ShortestChain(v.Binary, v.Imported, graph)
		if chain == nil {
			if v.Binary != "" {
				chain = []string{v.Binary, v.Imported}
			} else if v.Importer != "" {
				chain = []string{v.Importer, v.Imported}
			} else {
				chain = []string{v.Imported}
			}
		}
		t.Errorf("NEW violation:\n    %s", FormatChain(chain))
	}

	binKeys := make([]string, 0, len(known))
	for bk := range known {
		binKeys = append(binKeys, bk)
	}
	sort.Strings(binKeys)

	for _, bk := range binKeys {
		// The "" key is library scope: always active, never an unknown binary.
		if bk != "" {
			active := false
			for _, sb := range scannedBinaries {
				if pathMatches(bk, sb) {
					active = true
					break
				}
			}
			if !active {
				t.Errorf("knownViolations binary key %q matches no scanned binary — remove it or fix the path", bk)
				continue
			}
		}
		compKeys := make([]string, 0, len(known[bk]))
		for ck := range known[bk] {
			compKeys = append(compKeys, ck)
		}
		sort.Strings(compKeys)
		for _, ck := range compKeys {
			for i, kv := range known[bk][ck] {
				if !matchedEntries[entryKey{bk, ck, i}] {
					t.Errorf("stale entry in knownViolations: binary=%q component=%q imported=%q — remove it", bk, ck, kv.Imported)
				}
			}
		}
	}
}

// A single package matching ck must satisfy both halves: reachable from the
// binary AND able to reach the forbidden package.
func componentOnPath(binary, ck, forbidden string, pkgsForCK []string, reach func(string) map[string]bool) bool {
	if ck == "" {
		return true
	}
	if binary == "" {
		// Flat-scan violations have no binary root; a component key has no
		// meaningful path constraint without one.
		return false
	}
	binaryReach := reach(binary)
	for _, p := range pkgsForCK {
		if !binaryReach[p] {
			continue
		}
		if reach(p)[forbidden] {
			return true
		}
	}
	return false
}

func validateSkipBinaries(t testing.TB, skipBinaries, discoveredBinaries []string) {
	t.Helper()
	for _, skip := range skipBinaries {
		found := false
		for _, discovered := range discoveredBinaries {
			if pathMatches(skip, discovered) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("skipBinaries entry %q matches no discovered binary — remove it or fix the path", skip)
		}
	}
}

func scanBinaryViolations(graph map[string][]string, binaries []string, forbiddenPkgs []string) ([]Violation, map[string]bool) {
	var violations []Violation
	// unionReach accumulates every package reachable from any binary.
	// scanFlatViolations uses it to exclude binary-reachable packages from the
	// flat scope, so they are not double-reported.
	unionReach := make(map[string]bool)
	seen := make(map[Violation]bool)

	for _, bin := range binaries {
		for pkg := range bfsReachable(bin, graph) {
			unionReach[pkg] = true
			for _, imp := range graph[pkg] {
				if !isForbidden(imp, forbiddenPkgs) {
					continue
				}
				v := Violation{Binary: bin, Imported: imp}
				if !seen[v] {
					seen[v] = true
					violations = append(violations, v)
				}
			}
		}
	}
	return violations, unionReach
}

// scanFlatViolations covers packages no binary reaches, so library code is
// still audited.
func scanFlatViolations(graph map[string][]string, unionReach map[string]bool, forbiddenPkgs []string) []Violation {
	var violations []Violation
	seen := make(map[string]bool)

	for pkg, imports := range graph {
		if unionReach[pkg] {
			continue
		}
		for _, imp := range imports {
			if !isForbidden(imp, forbiddenPkgs) {
				continue
			}
			// NUL separator prevents "a/b"+"c" from colliding with "a"+"bc".
			key := pkg + "\x00" + imp
			if seen[key] {
				continue
			}
			seen[key] = true
			violations = append(violations, Violation{Importer: pkg, Imported: imp})
		}
	}
	return violations
}

// bfsReachable returns the set of packages reachable from root, inclusive.
// An absent root yields an empty set: it is not a real package, so returning it
// would make a typo'd component key look reachable.
func bfsReachable(root string, graph map[string][]string) map[string]bool {
	visited := make(map[string]bool)
	if _, ok := graph[root]; !ok {
		return visited
	}
	visited[root] = true
	queue := []string{root}
	for i := 0; i < len(queue); i++ {
		for _, dep := range graph[queue[i]] {
			if !visited[dep] {
				visited[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	return visited
}

// ShortestChain returns the shortest import path from→to in graph, inclusive.
// Returns nil if no path exists.
func ShortestChain(from, to string, graph map[string][]string) []string {
	if from == to {
		return []string{from}
	}

	parent := map[string]string{from: ""}
	queue := []string{from}
	for i := 0; i < len(queue); i++ {
		for _, next := range graph[queue[i]] {
			if _, seen := parent[next]; seen {
				continue
			}
			parent[next] = queue[i]
			if next == to {
				// Reconstruct path by following parent pointers from target
				// back to root, then reverse: BFS builds the path backward.
				var chain []string
				for p := to; p != from; p = parent[p] {
					chain = append(chain, p)
				}
				chain = append(chain, from)
				for l, r := 0, len(chain)-1; l < r; l, r = l+1, r-1 {
					chain[l], chain[r] = chain[r], chain[l]
				}
				return chain
			}
			queue = append(queue, next)
		}
	}
	return nil
}

// FormatChain renders an import chain as:
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

// pathMatches reports whether path equals pattern or is a sub-package of it.
// An empty pattern is a wildcard.
func pathMatches(pattern, path string) bool {
	bare := strings.TrimRight(pattern, "/")
	return bare == "" || path == bare || strings.HasPrefix(path, bare+"/")
}

func isForbidden(pkg string, forbiddenPkgs []string) bool {
	for _, prefix := range forbiddenPkgs {
		if pathMatches(prefix, pkg) {
			return true
		}
	}
	return false
}
