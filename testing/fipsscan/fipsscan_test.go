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

package fipsscan

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestModuleRoot(t *testing.T) {
	root := moduleRoot(t)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("moduleRoot returned %q but no go.mod found there: %v", root, err)
	}
}

func TestMatchesBinaryKey(t *testing.T) {
	tests := []struct {
		key    string
		binary string
		want   bool
	}{
		// wildcard
		{"", "github.com/foo/cmd/agent", true},
		// exact match
		{"github.com/foo/cmd/agent", "github.com/foo/cmd/agent", true},
		// module-root prefix
		{"github.com/foo", "github.com/foo/cmd/agent", true},
		// prefix with trailing slash in key (normalised)
		{"github.com/foo/", "github.com/foo/cmd/agent", true},
		// no false prefix: foobar must not match foo
		{"github.com/foo", "github.com/foobar/cmd/agent", false},
		// key longer than binary
		{"github.com/foo/cmd/agent/extra", "github.com/foo/cmd/agent", false},
	}
	for _, tc := range tests {
		got := matchesBinaryKey(tc.key, tc.binary)
		if got != tc.want {
			t.Errorf("matchesBinaryKey(%q, %q) = %v, want %v", tc.key, tc.binary, got, tc.want)
		}
	}
}

func TestIsForbidden(t *testing.T) {
	tests := []struct {
		pkg      string
		prefixes []string
		want     bool
	}{
		// exact match without trailing slash
		{"golang.org/x/crypto", []string{"golang.org/x/crypto/"}, true},
		// sub-package matched by prefix with trailing slash
		{"golang.org/x/crypto/md4", []string{"golang.org/x/crypto/"}, true},
		// sub-package matched by prefix without trailing slash
		{"golang.org/x/crypto/md4", []string{"golang.org/x/crypto"}, true},
		// no false prefix: cryptography must not match crypto
		{"golang.org/x/cryptography", []string{"golang.org/x/crypto/"}, false},
		// filippo.io prefix
		{"filippo.io/edwards25519", []string{"filippo.io/"}, true},
		// not matched
		{"github.com/safe/pkg", []string{"golang.org/x/crypto/"}, false},
	}
	for _, tc := range tests {
		got := isForbidden(tc.pkg, tc.prefixes)
		if got != tc.want {
			t.Errorf("isForbidden(%q, %v) = %v, want %v", tc.pkg, tc.prefixes, got, tc.want)
		}
	}
}

func TestShortestChain(t *testing.T) {
	graph := map[string][]string{
		"root":   {"a", "b"},
		"a":      {"c", "d"},
		"b":      {"d", "e"},
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
			name: "direct child",
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
			want: []string{"root", "a", "c", "target"},
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
			name: "leaf with no edges",
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

// TestCheckViolationsCrossBinaryAttribution is a regression test for the bug
// where a component reachable only from binary B could suppress a violation
// attributed to binary A, because markKnown checked component->importer
// reachability but not binary->component reachability.
func TestCheckViolationsCrossBinaryAttribution(t *testing.T) {
	// Import graph:
	//   cmd/binary-a  ->  importer  ->  golang.org/x/crypto/sha256
	//   cmd/binary-b  ->  comp-b    ->  importer  ->  golang.org/x/crypto/sha256
	//
	// comp-b can reach importer, but comp-b is only reachable from cmd/binary-b.
	// A violation attributed to cmd/binary-a must NOT be suppressed by the
	// comp-b entry registered under the "" wildcard binary key.
	importGraph := map[string][]string{
		"cmd/binary-a":               {"importer"},
		"cmd/binary-b":               {"comp-b"},
		"comp-b":                     {"importer"},
		"importer":                   {"golang.org/x/crypto/sha256"},
		"golang.org/x/crypto/sha256": {},
	}
	mains := []string{"cmd/binary-a", "cmd/binary-b"}
	violations := []Violation{
		{Binary: "cmd/binary-a", Importer: "importer", Imported: "golang.org/x/crypto/sha256"},
		{Binary: "cmd/binary-b", Importer: "importer", Imported: "golang.org/x/crypto/sha256"},
	}
	// comp-b is documented under the wildcard binary key "".
	// It can reach importer, but must NOT suppress binary-a's violation.
	knownViolations := map[string]map[string][]KnownViolation{
		"": {
			"comp-b": {{Reason: "ok for binary-b"}},
		},
	}

	var errors []string
	tb := &captureT{T: t, errorf: func(f string, a ...any) {
		errors = append(errors, fmt.Sprintf(f, a...))
	}}
	checkViolations(tb, violations, importGraph, mains, knownViolations)

	// binary-a's violation must be reported as NEW (comp-b is not reachable from it).
	if len(errors) != 1 || !strings.Contains(errors[0], "NEW violation") {
		t.Errorf("expected exactly one NEW violation for cmd/binary-a, got %v", errors)
	}
}

// captureT wraps *testing.T and redirects Errorf so tests can inspect failures.
type captureT struct {
	*testing.T
	errorf func(string, ...any)
}

func (c *captureT) Errorf(format string, args ...any) { c.errorf(format, args...) }
func (c *captureT) Helper()                           { c.T.Helper() }

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
			name:  "single",
			chain: []string{"pkg/a"},
			want:  "pkg/a",
		},
		{
			name:  "two",
			chain: []string{"pkg/a", "pkg/b"},
			want:  "pkg/a\n      -> pkg/b",
		},
		{
			name:  "three",
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
