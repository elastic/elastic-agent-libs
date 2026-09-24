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

package fipsscan

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Section 1: pathMatches
// -----------------------------------------------------------------------------

// TestPathMatches covers the shared prefix-matching rule used for binary keys,
// component keys and KnownViolation.Imported.
//
// Rules:
//   - "" is a wildcard and matches anything.
//   - a trailing slash in the pattern is stripped before matching.
//   - a match is either exact or on a "/" boundary, so "foo" never matches "foobar".
func TestPathMatches(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// wildcard matches anything
		{"", "github.com/foo/cmd/agent", true},
		// exact match
		{"github.com/foo/cmd/agent", "github.com/foo/cmd/agent", true},
		// sub-package match, pattern without trailing slash
		{"github.com/foo", "github.com/foo/cmd/agent", true},
		// sub-package match, pattern with trailing slash (normalised away)
		{"github.com/foo/", "github.com/foo/cmd/agent", true},
		// no false prefix: "foo" is not a prefix of "foobar" on a path boundary
		{"github.com/foo", "github.com/foobar", false},
		{"github.com/foo", "github.com/foobar/pkg", false},
		// pattern longer than the path
		{"github.com/foo/cmd/agent/extra", "github.com/foo/cmd/agent", false},
		// module root without a github.com host
		{"filippo.io", "filippo.io/edwards25519", true},
		// empty path with empty pattern
		{"", "", true},
	}

	for _, tc := range tests {
		got := pathMatches(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("pathMatches(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Section 2: bfsReachable
// -----------------------------------------------------------------------------

// TestBfsReachable_Linear checks a simple chain.
//
//	a ─→ b ─→ c ─→ d
//
// Expected: everything downstream of a, plus a itself.
func TestBfsReachable_Linear(t *testing.T) {
	graph := map[string][]string{
		"a": {"b"},
		"b": {"c"},
		"c": {"d"},
		"d": {},
	}

	got := bfsReachable("a", graph)
	want := map[string]bool{"a": true, "b": true, "c": true, "d": true}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("bfsReachable(a) = %v, want %v", got, want)
	}
}

// TestBfsReachable_Diamond checks that a node reachable through two different
// parents appears exactly once and does not confuse the traversal.
//
//	root ─→ a ─┐
//	  └──→ b ─┴─→ shared
//
// Expected: root, a, b, shared.
func TestBfsReachable_Diamond(t *testing.T) {
	graph := map[string][]string{
		"root":   {"a", "b"},
		"a":      {"shared"},
		"b":      {"shared"},
		"shared": {},
	}

	got := bfsReachable("root", graph)
	want := map[string]bool{"root": true, "a": true, "b": true, "shared": true}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("bfsReachable(root) = %v, want %v", got, want)
	}
}

// TestBfsReachable_Cycle checks that a cycle terminates instead of looping.
//
//	a ─→ b ─→ c ─┐
//	↑            │
//	└────────────┘
//
// Expected: a, b, c — and the call returns.
func TestBfsReachable_Cycle(t *testing.T) {
	graph := map[string][]string{
		"a": {"b"},
		"b": {"c"},
		"c": {"a"},
	}

	got := bfsReachable("a", graph)
	want := map[string]bool{"a": true, "b": true, "c": true}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("bfsReachable(a) = %v, want %v", got, want)
	}
}

// TestBfsReachable_Disconnected checks that unrelated components are excluded.
//
//	a ─→ b        x ─→ y   (separate component)
//
// Expected: only a and b.
func TestBfsReachable_Disconnected(t *testing.T) {
	graph := map[string][]string{
		"a": {"b"},
		"b": {},
		"x": {"y"},
		"y": {},
	}

	got := bfsReachable("a", graph)
	want := map[string]bool{"a": true, "b": true}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("bfsReachable(a) = %v, want %v", got, want)
	}
}

// TestBfsReachable_RootNotInGraph checks the behaviour for an unknown root.
//
//	a ─→ b        (root "zz" is absent)
//
// Expected: empty set. An unknown package has no known dependencies, so it must
// not be reported as reachable from itself either — otherwise a typo in a
// component key would silently look like a real package.
func TestBfsReachable_RootNotInGraph(t *testing.T) {
	graph := map[string][]string{
		"a": {"b"},
		"b": {},
	}

	got := bfsReachable("zz", graph)

	if len(got) != 0 {
		t.Errorf("bfsReachable(zz) = %v, want empty set", got)
	}
}

// TestBfsReachable_LeafNode checks a package that exists but imports nothing.
//
//	a ─→ b        (start from b)
//
// Expected: just b.
func TestBfsReachable_LeafNode(t *testing.T) {
	graph := map[string][]string{
		"a": {"b"},
		"b": {},
	}

	got := bfsReachable("b", graph)
	want := map[string]bool{"b": true}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("bfsReachable(b) = %v, want %v", got, want)
	}
}

// -----------------------------------------------------------------------------
// Section 3: ShortestChain and FormatChain
// -----------------------------------------------------------------------------

// TestShortestChain checks that the reported chain is always the shortest one.
//
//	root ─→ a ─→ c ─→ target
//	 │      └──→ d ─→ e
//	 └───→ b ─→ target
//	          └─→ e
//
// Expected: the two-hop route wins over the three-hop route.
func TestShortestChain(t *testing.T) {
	graph := map[string][]string{
		"root":   {"a", "b"},
		"a":      {"c", "d"},
		"b":      {"target", "e"},
		"c":      {"target"},
		"d":      {"e"},
		"e":      {},
		"target": {},
	}

	tests := []struct {
		name string
		from string
		to   string
		want []string
	}{
		{
			name: "direct neighbour",
			from: "root",
			to:   "a",
			want: []string{"root", "a"},
		},
		{
			name: "two hops",
			from: "root",
			to:   "c",
			want: []string{"root", "a", "c"},
		},
		{
			name: "shortest of two paths",
			from: "root",
			to:   "target",
			want: []string{"root", "b", "target"},
		},
		{
			name: "same node",
			from: "root",
			to:   "root",
			want: []string{"root"},
		},
		{
			name: "no path",
			from: "root",
			to:   "unreachable",
			want: nil,
		},
		{
			name: "leaf reachable two ways picks the shorter",
			from: "root",
			to:   "e",
			want: []string{"root", "b", "e"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ShortestChain(tc.from, tc.to, graph)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ShortestChain(%q, %q) = %v, want %v", tc.from, tc.to, got, tc.want)
			}
		})
	}
}

// TestFormatChain checks the indented rendering used in failure output.
func TestFormatChain(t *testing.T) {
	tests := []struct {
		name  string
		chain []string
		want  string
	}{
		{
			name:  "empty",
			chain: []string{},
			want:  "",
		},
		{
			name:  "single element",
			chain: []string{"pkg/a"},
			want:  "pkg/a",
		},
		{
			name:  "two elements",
			chain: []string{"pkg/a", "pkg/b"},
			want:  "pkg/a\n      -> pkg/b",
		},
		{
			name:  "three elements",
			chain: []string{"pkg/a", "pkg/b", "pkg/c"},
			want:  "pkg/a\n      -> pkg/b\n      -> pkg/c",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatChain(tc.chain)
			if got != tc.want {
				t.Errorf("FormatChain(%v) =\n%q\nwant:\n%q", tc.chain, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Section 4: violation matching
// -----------------------------------------------------------------------------

// TestCheckViolations_NewViolation_NoEntry — a violation with no allowlist entry
// at all.
//
//	binary ─→ forbidden
//
// Expected: 1 NEW error.
func TestCheckViolations_NewViolation_NoEntry(t *testing.T) {
	const (
		binary    = "github.com/foo/cmd/agent"
		forbidden = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:    {forbidden},
		forbidden: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbidden}}
	known := map[string]map[string][]KnownViolation{}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Errorf("expected 1 NEW error, got %d: %v", n, *errs)
	}
}

// TestCheckViolations_KnownAndMatched_FlatBinary — component key "" covers any
// path from the binary to the forbidden package.
//
//	binary ─→ forbidden
//
// Expected: 0 errors.
func TestCheckViolations_KnownAndMatched_FlatBinary(t *testing.T) {
	const (
		binary    = "github.com/foo/cmd/agent"
		forbidden = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:    {forbidden},
		forbidden: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbidden}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			"": {{Imported: forbidden, Reason: "accepted for now"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestCheckViolations_KnownAndMatched_ComponentOnPath — the component key is
// enforced and the component really sits on the path.
//
//	binary ─→ vendor/comp/pkg ─→ forbidden
//
// Component key "github.com/vendor/comp" matches "github.com/vendor/comp/pkg".
//
// Expected: 0 errors.
func TestCheckViolations_KnownAndMatched_ComponentOnPath(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		componentKey  = "github.com/vendor/comp"
		componentPkg  = "github.com/vendor/comp/pkg"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {componentPkg},
		componentPkg:  {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			componentKey: {{Imported: forbiddenPath, Reason: "comp needs md4"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestCheckViolations_ComponentExistsButNotOnPath — the component is reachable
// from the binary but never reaches the forbidden package. The forbidden package
// arrives through a different edge.
//
//	binary ─→ vendor/comp/pkg      (dead end for forbidden)
//	binary ─→ forbidden            (direct, bypasses the component)
//
// Expected: 1 NEW error — the entry only covers violations that go through the
// component.
func TestCheckViolations_ComponentExistsButNotOnPath(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		componentKey  = "github.com/vendor/comp"
		componentPkg  = "github.com/vendor/comp/pkg"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {componentPkg, forbiddenPath},
		componentPkg:  {},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			componentKey: {{Imported: forbiddenPath, Reason: "comp needs md4"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Errorf("expected 1 NEW error, got %d: %v", n, *errs)
	}
}

// TestCheckViolations_ConjunctionBug_TwoDifferentPackages — the component check
// must be satisfied by ONE package, not by two packages each covering half of it.
//
//	cmd/binary-a ─→ vendor/comp/pkg-1   (reachable from a, but never reaches forbidden)
//	cmd/binary-a ─→ forbidden           (direct, this is the violation)
//	cmd/binary-b ─→ vendor/comp/pkg-2 ─→ forbidden   (reaches forbidden, but not from a)
//
// Component key "github.com/vendor/comp" matches pkg-1 and pkg-2:
//
//	pkg-1: reachable from binary-a yes, reaches forbidden no
//	pkg-2: reachable from binary-a no,  reaches forbidden yes
//
// Expected: 1 NEW error — no single package satisfies both halves.
func TestCheckViolations_ConjunctionBug_TwoDifferentPackages(t *testing.T) {
	const (
		binaryA       = "github.com/foo/cmd/binary-a"
		binaryB       = "github.com/foo/cmd/binary-b"
		componentKey  = "github.com/vendor/comp"
		componentPkg1 = "github.com/vendor/comp/pkg-1"
		componentPkg2 = "github.com/vendor/comp/pkg-2"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binaryA:       {componentPkg1, forbiddenPath},
		binaryB:       {componentPkg2},
		componentPkg1: {},
		componentPkg2: {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binaryA, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binaryA: {
			componentKey: {{Imported: forbiddenPath, Reason: "only valid through comp"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binaryA, binaryB}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Errorf("expected 1 NEW error, got %d: %v", n, *errs)
	}
}

// TestCheckViolations_ComponentSubPackageMatches — the component key is a module
// root, the package on the path is a sub-package of it.
//
//	binary ─→ gokrb5/v8/crypto/aescts ─→ forbidden
//
// Expected: 0 errors.
func TestCheckViolations_ComponentSubPackageMatches(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		componentKey  = "github.com/elastic/gokrb5/v8"
		componentPkg  = "github.com/elastic/gokrb5/v8/crypto/aescts"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {componentPkg},
		componentPkg:  {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			componentKey: {{Imported: forbiddenPath, Reason: "kerberos crypto"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestCheckViolations_BinaryKeyPrefixMatch — the binary key is a module-root
// prefix of the real binary import path.
//
//	binary key: github.com/elastic/beats/v7/x-pack
//	binary:     github.com/elastic/beats/v7/x-pack/filebeat ─→ forbidden
//
// Expected: 0 errors — the key covers the binary.
func TestCheckViolations_BinaryKeyPrefixMatch(t *testing.T) {
	const (
		binaryKey     = "github.com/elastic/beats/v7/x-pack"
		binary        = "github.com/elastic/beats/v7/x-pack/filebeat"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binaryKey: {
			"": {{Imported: forbiddenPath, Reason: "x-pack wide exception"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestCheckViolations_BinaryKeyNoPrefixFalsePositive — a binary key must only
// match on a "/" boundary.
//
//	binary key: github.com/elastic/beats
//	binary:     github.com/elastic/beatsagent ─→ forbidden
//
// Expected: 1 NEW error — "beats" does not cover "beatsagent".
func TestCheckViolations_BinaryKeyNoPrefixFalsePositive(t *testing.T) {
	const (
		binaryKey     = "github.com/elastic/beats"
		binary        = "github.com/elastic/beatsagent"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binaryKey: {
			"": {{Imported: forbiddenPath, Reason: "beats only"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Errorf("expected 1 NEW error, got %d: %v", n, *errs)
	}
}

// TestCheckViolations_CrossBinaryIsolation — an entry filed under binary-a must
// not cover the same forbidden import pulled in by binary-b.
//
//	cmd/binary-a ─→ forbidden   (covered by the entry)
//	cmd/binary-b ─→ forbidden   (not covered)
//
// Expected: 1 NEW error, and it names binary-b.
func TestCheckViolations_CrossBinaryIsolation(t *testing.T) {
	const (
		binaryA       = "github.com/foo/cmd/binary-a"
		binaryB       = "github.com/foo/cmd/binary-b"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binaryA:       {forbiddenPath},
		binaryB:       {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{
		{Binary: binaryA, Imported: forbiddenPath},
		{Binary: binaryB, Imported: forbiddenPath},
	}
	known := map[string]map[string][]KnownViolation{
		binaryA: {
			"": {{Imported: forbiddenPath, Reason: "binary-a only"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binaryA, binaryB}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Fatalf("expected 1 NEW error, got %d: %v", n, *errs)
	}
	if n := countContaining(*errs, binaryB); n != 1 {
		t.Errorf("expected the NEW error to name %q, got: %v", binaryB, *errs)
	}
}

// TestCheckViolations_ImportedPrefixMatch — KnownViolation.Imported is a module
// root that covers a specific forbidden sub-package.
//
//	binary ─→ golang.org/x/crypto/md4
//	entry Imported: golang.org/x/crypto
//
// Expected: 0 errors.
func TestCheckViolations_ImportedPrefixMatch(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		importedKey   = "golang.org/x/crypto"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			"": {{Imported: importedKey, Reason: "all of x/crypto accepted here"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestCheckViolations_MultipleForbiddenSameComponent — one component key holds a
// separate entry per forbidden package.
//
//	binary ─→ vendor/comp/pkg ─→ forbidden-1
//	                          └─→ forbidden-2
//
// Expected: 0 errors.
func TestCheckViolations_MultipleForbiddenSameComponent(t *testing.T) {
	const (
		binary       = "github.com/foo/cmd/agent"
		componentKey = "github.com/vendor/comp"
		componentPkg = "github.com/vendor/comp/pkg"
		forbidden1   = "golang.org/x/crypto/md4"
		forbidden2   = "golang.org/x/crypto/blowfish"
	)

	graph := map[string][]string{
		binary:       {componentPkg},
		componentPkg: {forbidden1, forbidden2},
		forbidden1:   {},
		forbidden2:   {},
	}
	violations := []Violation{
		{Binary: binary, Imported: forbidden1},
		{Binary: binary, Imported: forbidden2},
	}
	known := map[string]map[string][]KnownViolation{
		binary: {
			componentKey: {
				{Imported: forbidden1, Reason: "comp needs md4"},
				{Imported: forbidden2, Reason: "comp needs blowfish"},
			},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// -----------------------------------------------------------------------------
// Section 5: stale detection
// -----------------------------------------------------------------------------

// TestStale_ViolationFixed — the dependency is gone but the entry is still listed.
//
//	binary                      (no edge to forbidden any more)
//
// Expected: 1 stale error.
func TestStale_ViolationFixed(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary: {},
	}
	known := map[string]map[string][]KnownViolation{
		binary: {
			"": {{Imported: forbiddenPath, Reason: "was needed once"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, nil, graph, []string{binary}, known)

	if n := countContaining(*errs, "stale"); n != 1 {
		t.Errorf("expected 1 stale error, got %d: %v", n, *errs)
	}
	if len(*errs) != 1 {
		t.Errorf("expected exactly 1 error in total, got %d: %v", len(*errs), *errs)
	}
}

// TestStale_ComponentRemovedFromGraph — the forbidden import is still there but
// the component it used to come through is gone from the dependency tree.
//
//	binary ─→ forbidden          (direct; the old component is absent)
//
// Expected: 1 NEW error (the entry no longer matches) and 1 stale error.
func TestStale_ComponentRemovedFromGraph(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		removedComp   = "github.com/vendor/removed"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			removedComp: {{Imported: forbiddenPath, Reason: "came through the removed component"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Errorf("expected 1 NEW error, got %d: %v", n, *errs)
	}
	if n := countContaining(*errs, "stale"); n != 1 {
		t.Errorf("expected 1 stale error, got %d: %v", n, *errs)
	}
}

// TestStale_ComponentTypo_BothNewAndStale — a typo in the component key breaks
// the entry in both directions at once.
//
//	binary ─→ vendor/comp/pkg ─→ forbidden
//	entry component key: github.com/vendor/kmop   (typo, matches nothing)
//
// Expected: 1 NEW error and 1 stale error.
func TestStale_ComponentTypo_BothNewAndStale(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		componentPkg  = "github.com/vendor/comp/pkg"
		typoComponent = "github.com/vendor/kmop"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {componentPkg},
		componentPkg:  {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			typoComponent: {{Imported: forbiddenPath, Reason: "typo in the component key"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Errorf("expected 1 NEW error, got %d: %v", n, *errs)
	}
	if n := countContaining(*errs, "stale"); n != 1 {
		t.Errorf("expected 1 stale error, got %d: %v", n, *errs)
	}
}

// TestStale_NotStale_ViolationStillPresent — a matched entry is never stale.
//
//	binary ─→ forbidden
//
// Expected: 0 errors.
func TestStale_NotStale_ViolationStillPresent(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			"": {{Imported: forbiddenPath, Reason: "still needed"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestStale_TwoEntries_IndependentTracking — entries under the same key are
// tracked one by one.
//
//	binary ─→ forbidden-1        (forbidden-2 is gone)
//
// Expected: 1 stale error, naming forbidden-2 only.
func TestStale_TwoEntries_IndependentTracking(t *testing.T) {
	const (
		binary     = "github.com/foo/cmd/agent"
		forbidden1 = "golang.org/x/crypto/md4"
		forbidden2 = "golang.org/x/crypto/blowfish"
	)

	graph := map[string][]string{
		binary:     {forbidden1},
		forbidden1: {},
	}
	violations := []Violation{{Binary: binary, Imported: forbidden1}}
	known := map[string]map[string][]KnownViolation{
		binary: {
			"": {
				{Imported: forbidden1, Reason: "still active"},
				{Imported: forbidden2, Reason: "now fixed - should be stale"},
			},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "stale"); n != 1 {
		t.Fatalf("expected 1 stale error, got %d: %v", n, *errs)
	}
	if n := countContaining(*errs, forbidden2); n != 1 {
		t.Errorf("expected the stale error to name %q, got: %v", forbidden2, *errs)
	}
	if n := countContaining(*errs, forbidden1); n != 0 {
		t.Errorf("did not expect any error naming %q, got: %v", forbidden1, *errs)
	}
}

// TestStale_UnknownBinaryKey_Error — a binary key that matches no scanned binary
// is its own error class, separate from stale.
//
// Expected: an error naming the unknown key.
func TestStale_UnknownBinaryKey_Error(t *testing.T) {
	const (
		typoKey       = "github.com/foo/cmd/typo"
		scannedBinary = "github.com/foo/cmd/agent"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		scannedBinary: {},
	}
	known := map[string]map[string][]KnownViolation{
		typoKey: {
			"": {{Imported: forbiddenPath, Reason: "binary name has a typo"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, nil, graph, []string{scannedBinary}, known)

	if n := countContaining(*errs, typoKey); n != 1 {
		t.Errorf("expected 1 error naming the unknown binary key %q, got %d: %v", typoKey, n, *errs)
	}
}

// TestStale_LibraryBinaryKey_NeverUnknown — the "" binary key is always active,
// even when the module has no binaries at all.
//
//	library/pkg ─→ forbidden     (flat scan, Binary is "")
//
// Expected: 0 errors — the violation matches and "" never triggers the
// unknown-binary error.
func TestStale_LibraryBinaryKey_NeverUnknown(t *testing.T) {
	const (
		libraryPkg    = "github.com/foo/library/pkg"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		libraryPkg:    {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: "", Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		"": {
			"": {{Imported: forbiddenPath, Reason: "library level exception"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, nil, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestStale_LibraryScope_Stale — the "" binary key entry goes stale once the
// library violation is fixed.
//
//	library/pkg                  (no edge to forbidden any more)
//
// Expected: 1 stale error.
func TestStale_LibraryScope_Stale(t *testing.T) {
	const (
		libraryPkg    = "github.com/foo/library/pkg"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		libraryPkg: {},
	}
	known := map[string]map[string][]KnownViolation{
		"": {
			"": {{Imported: forbiddenPath, Reason: "no longer imported"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, nil, graph, nil, known)

	if n := countContaining(*errs, "stale"); n != 1 {
		t.Errorf("expected 1 stale error, got %d: %v", n, *errs)
	}
}

// -----------------------------------------------------------------------------
// Section 6: scope - flat scan plus per-binary BFS
// -----------------------------------------------------------------------------

// TestScope_FlatScanCatchesLibraryPackages — a package that no binary imports is
// still scanned, and its violation carries an empty Binary.
//
//	cmd/binary  ─→ forbidden-1     (binary scope, covered by an entry)
//	library/pkg ─→ forbidden-2     (flat scan, not covered)
//
// Expected: 1 NEW error, for the flat-scan violation.
func TestScope_FlatScanCatchesLibraryPackages(t *testing.T) {
	const (
		binary     = "github.com/foo/cmd/binary"
		libraryPkg = "github.com/foo/library/pkg"
		forbidden1 = "golang.org/x/crypto/md4"
		forbidden2 = "golang.org/x/crypto/blowfish"
	)

	graph := map[string][]string{
		binary:     {forbidden1},
		libraryPkg: {forbidden2},
		forbidden1: {},
		forbidden2: {},
	}
	violations := []Violation{
		{Binary: binary, Imported: forbidden1},
		{Binary: "", Imported: forbidden2},
	}
	known := map[string]map[string][]KnownViolation{
		binary: {
			"": {{Imported: forbidden1, Reason: "binary scope exception"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Fatalf("expected 1 NEW error, got %d: %v", n, *errs)
	}
	if n := countContaining(*errs, forbidden2); n != 1 {
		t.Errorf("expected the NEW error to name %q, got: %v", forbidden2, *errs)
	}
}

// TestScope_FlatScanViolation_CoveredByLibraryEntry — a flat-scan violation is
// covered by the "" binary key.
//
//	library/pkg ─→ forbidden
//
// Expected: 0 errors.
func TestScope_FlatScanViolation_CoveredByLibraryEntry(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/binary"
		libraryPkg    = "github.com/foo/library/pkg"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {},
		libraryPkg:    {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: "", Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		"": {
			"": {{Imported: forbiddenPath, Reason: "library level exception"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// -----------------------------------------------------------------------------
// Section 7: skipBinaries validation
// -----------------------------------------------------------------------------

// TestValidateSkipBinaries_UnknownEntry_Error — a skip entry that matches no
// discovered binary is a mistake.
//
// Expected: 1 error naming the unknown entry.
func TestValidateSkipBinaries_UnknownEntry_Error(t *testing.T) {
	const (
		mistyped   = "github.com/foo/cmd/mistyped"
		discovered = "github.com/foo/cmd/agent"
	)

	ct, errs := collectErrors(t)
	validateSkipBinaries(ct, []string{mistyped}, []string{discovered})

	if len(*errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(*errs), *errs)
	}
	if !strings.Contains((*errs)[0], mistyped) {
		t.Errorf("expected the error to name %q, got: %v", mistyped, *errs)
	}
}

// TestValidateSkipBinaries_PrefixMatch_NoError — a module-root skip entry covers
// longer binary paths underneath it.
//
// Expected: 0 errors.
func TestValidateSkipBinaries_PrefixMatch_NoError(t *testing.T) {
	const (
		skipPrefix = "github.com/foo/dev-tools"
		discovered = "github.com/foo/dev-tools/cmd/lint"
	)

	ct, errs := collectErrors(t)
	validateSkipBinaries(ct, []string{skipPrefix}, []string{discovered})

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestValidateSkipBinaries_ExactMatch_NoError — an exact skip entry.
//
// Expected: 0 errors.
func TestValidateSkipBinaries_ExactMatch_NoError(t *testing.T) {
	const binary = "github.com/foo/cmd/tool"

	ct, errs := collectErrors(t)
	validateSkipBinaries(ct, []string{binary}, []string{binary})

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestValidateSkipBinaries_MultipleEntries_OneMissing — only the entry that
// matches nothing is reported.
//
// Expected: 1 error, naming the missing entry only.
func TestValidateSkipBinaries_MultipleEntries_OneMissing(t *testing.T) {
	const (
		good    = "github.com/foo/cmd/tool"
		missing = "github.com/foo/cmd/gone"
	)

	ct, errs := collectErrors(t)
	validateSkipBinaries(ct, []string{good, missing}, []string{good})

	if len(*errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(*errs), *errs)
	}
	if !strings.Contains((*errs)[0], missing) {
		t.Errorf("expected the error to name %q, got: %v", missing, *errs)
	}
	if strings.Contains((*errs)[0], good) {
		t.Errorf("did not expect the error to name %q, got: %v", good, *errs)
	}
}

// -----------------------------------------------------------------------------
// Section 8: helpers
// -----------------------------------------------------------------------------

// captureT wraps *testing.T and redirects Errorf so tests can inspect reported failures.
type captureT struct {
	*testing.T
	errorf func(string, ...any)
	fatalf func(string, ...any)
}

func (c *captureT) Errorf(format string, args ...any) { c.errorf(format, args...) }

func (c *captureT) Fatalf(format string, args ...any) {
	if c.fatalf != nil {
		c.fatalf(format, args...)
	} else {
		c.T.Fatalf(format, args...)
	}
}

func (c *captureT) Helper() { c.T.Helper() }

// collectErrors returns a testing.TB that appends every Errorf call to a slice.
func collectErrors(t *testing.T) (*captureT, *[]string) {
	var errs []string
	ct := &captureT{T: t, errorf: func(f string, a ...any) {
		errs = append(errs, fmt.Sprintf(f, a...))
	}}
	return ct, &errs
}

// countContaining returns how many collected errors contain marker.
func countContaining(errs []string, marker string) int {
	n := 0
	for _, e := range errs {
		if strings.Contains(e, marker) {
			n++
		}
	}
	return n
}

// -----------------------------------------------------------------------------
// Section 9: Regression tests for known bugs
// -----------------------------------------------------------------------------

// TestBug1_ScanBinaryViolations_ForbiddenImportsForbidden — when a forbidden
// package under prefix A imports another forbidden package under prefix B,
// scanBinaryViolations must report both violations.
//
// The isForbidden(pkg) guard in the scan loop was silently skipping all imports
// of forbidden packages, causing the inner violation to be dropped entirely.
//
//	binary → lib/pkg → golang.org/x/crypto/md4 → filippo.io/edwards25519
//	                      ^--- forbidden (A)           ^--- forbidden (B)
//
// Expected: 2 violations — one for each forbidden package.
// Bug: 1 violation — filippo.io/edwards25519 is silently dropped.
func TestScanBinaryViolations_ForbiddenImportsForbidden_BothReported(t *testing.T) {
	const (
		binary     = "github.com/foo/cmd/agent"
		lib        = "github.com/foo/lib/pkg"
		forbiddenA = "golang.org/x/crypto/md4"
		forbiddenB = "filippo.io/edwards25519"
	)

	graph := map[string][]string{
		binary:     {lib},
		lib:        {forbiddenA},
		forbiddenA: {forbiddenB},
		forbiddenB: {},
	}

	violations, _ := scanBinaryViolations(graph, []string{binary}, []string{"golang.org/x/crypto/", "filippo.io/"})

	found := map[string]bool{}
	for _, v := range violations {
		if v.Binary == binary {
			found[v.Imported] = true
		}
	}

	for _, want := range []string{forbiddenA, forbiddenB} {
		if !found[want] {
			t.Errorf("missing violation {binary=%q, imported=%q}; got violations: %v", binary, want, violations)
		}
	}
}

// TestBug1_ScanFlatViolations_ForbiddenImportsForbidden — same isForbidden guard
// bug, but in scanFlatViolations. When a forbidden package under prefix A imports
// another forbidden package under prefix B, the inner violation must be reported.
//
//	lib/pkg → golang.org/x/crypto/md4 → filippo.io/edwards25519
//	           ^--- forbidden (A)           ^--- forbidden (B)
//
// Expected: 2 flat-scan violations.
// Bug: 1 — filippo.io/edwards25519 is silently dropped.
func TestScanFlatViolations_ForbiddenImportsForbidden_BothReported(t *testing.T) {
	const (
		lib        = "github.com/foo/lib/pkg"
		forbiddenA = "golang.org/x/crypto/md4"
		forbiddenB = "filippo.io/edwards25519"
	)

	graph := map[string][]string{
		lib:        {forbiddenA},
		forbiddenA: {forbiddenB},
		forbiddenB: {},
	}

	violations := scanFlatViolations(graph, map[string]bool{}, []string{"golang.org/x/crypto/", "filippo.io/"})

	found := map[string]bool{}
	for _, v := range violations {
		found[v.Imported] = true
	}

	for _, want := range []string{forbiddenA, forbiddenB} {
		if !found[want] {
			t.Errorf("missing flat-scan violation {imported=%q}; got violations: %v", want, violations)
		}
	}
}

// TestBug1_FalseStale_InnerViolationDropped — end-to-end consequence of the
// isForbidden guard bug: when the inner violation (forbiddenB) is silently
// dropped, a valid allowlist entry for it is incorrectly reported as stale.
//
//	binary → lib/pkg → forbiddenA → forbiddenB
//
// Both violations are real and both allowlist entries are active. Expected: 0
// errors. Bug: 1 stale error for the forbiddenB entry (violation was dropped).
func TestCheckViolations_ForbiddenChain_AllViolationsMatchedNoFalseStale(t *testing.T) {
	const (
		binary     = "github.com/foo/cmd/agent"
		lib        = "github.com/foo/lib/pkg"
		forbiddenA = "golang.org/x/crypto/md4"
		forbiddenB = "filippo.io/edwards25519"
	)

	graph := map[string][]string{
		binary:     {lib},
		lib:        {forbiddenA},
		forbiddenA: {forbiddenB},
		forbiddenB: {},
	}

	violations, _ := scanBinaryViolations(graph, []string{binary}, []string{"golang.org/x/crypto/", "filippo.io/"})

	known := map[string]map[string][]KnownViolation{
		binary: {
			"": {
				{Imported: forbiddenA, Reason: "crypto/md4 used by lib"},
				{Imported: forbiddenB, Reason: "filippo.io/edwards25519 imported by crypto/md4"},
			},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if len(*errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(*errs), *errs)
	}
}

// TestBug2_FlatScanViolation_ImporterAbsentFromErrorMessage — for flat-scan NEW
// violations, the error message must name the library package that imports the
// forbidden package. Without it the output is just the forbidden package name,
// which gives no actionable information.
//
//	lib/pkg → golang.org/x/crypto/md4
//
// Expected: the NEW error message contains "lib/pkg".
// Bug: the message only contains "golang.org/x/crypto/md4" — the importer is lost.
func TestCheckViolations_FlatScanNewError_NamesImporter(t *testing.T) {
	const (
		lib           = "github.com/foo/lib/pkg"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		lib:           {forbiddenPath},
		forbiddenPath: {},
	}
	violations := []Violation{{Binary: "", Importer: lib, Imported: forbiddenPath}}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, nil, nil)

	if n := countContaining(*errs, "NEW"); n != 1 {
		t.Fatalf("expected 1 NEW error, got %d: %v", n, *errs)
	}
	if n := countContaining(*errs, lib); n == 0 {
		t.Errorf("NEW error must name the importer %q to be actionable; got: %v", lib, *errs)
	}
}

// TestBug3_ComponentCheck_FlatScan_BinaryScopePackageCoversLibraryViolation —
// componentOnPath skips the binaryReach guard when binary=="", allowing a
// package that is exclusively in a binary's dependency tree to silently validate
// a flat-scan violation it has nothing to do with.
//
//	binary  → comp/pkg → forbidden    (binary scope)
//	lib/pkg → forbidden                (flat-scan violation, Binary="")
//
// Entry {"": {"comp": [{Imported: forbidden}]}}: comp/pkg reaches forbidden, so
// componentOnPath returns true — but comp/pkg is unreachable from lib/pkg. The
// flat-scan violation must not be suppressed by a binary-scope component package.
//
// Expected: at least 1 NEW error for the uncovered flat-scan violation.
// Bug: 0 errors — the entry unsoundly covers the flat-scan violation.
func TestCheckViolations_FlatScan_BinaryScopeComponentDoesNotCoverLibraryViolation(t *testing.T) {
	const (
		binary        = "github.com/foo/cmd/agent"
		componentKey  = "github.com/vendor/comp"
		componentPkg  = "github.com/vendor/comp/pkg"
		lib           = "github.com/foo/lib/pkg"
		forbiddenPath = "golang.org/x/crypto/md4"
	)

	graph := map[string][]string{
		binary:        {componentPkg},
		componentPkg:  {forbiddenPath},
		lib:           {forbiddenPath},
		forbiddenPath: {},
	}
	// Only the flat-scan violation — comp/pkg is binary-scope, not lib-scope.
	violations := []Violation{{Binary: "", Imported: forbiddenPath}}
	known := map[string]map[string][]KnownViolation{
		"": {
			componentKey: {{Imported: forbiddenPath, Reason: "binary-scope comp must not cover lib violation"}},
		},
	}

	ct, errs := collectErrors(t)
	checkViolations(ct, violations, graph, []string{binary}, known)

	if n := countContaining(*errs, "NEW"); n < 1 {
		t.Errorf("expected at least 1 NEW error (flat-scan violation must not be suppressed by a binary-scope component), got %d: %v", n, *errs)
	}
}
