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

package mapstr

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	structform "github.com/elastic/go-structform"
	"github.com/elastic/go-structform/gotype"
	sfjson "github.com/elastic/go-structform/json"
)

// TestFoldMatchesReflection verifies that the Fold method produces
// byte-identical JSON to go-structform's default reflection path.
func TestFoldMatchesReflection(t *testing.T) {
	tests := map[string]M{
		"flat strings":    {"message": "hello world", "level": "info"},
		"nested maps":     {"host": M{"name": "web-01", "os": M{"type": "linux"}}},
		"mixed types":     {"name": "test", "count": 42, "rate": 3.14, "ok": true, "tags": []string{"a", "b"}},
		"nil values":      {"present": "yes", "absent": nil},
		"empty map":       {},
		"deeply nested":   {"a": M{"b": M{"c": M{"d": "deep"}}}},
		"array of mixed":  {"items": []interface{}{"one", 2, true, nil, M{"nested": "map"}}},
		"int types":       {"i": 1, "i64": int64(99), "u64": uint64(42)},
		"realistic event": {"message": "log line", "agent": M{"name": "filebeat", "version": "8.17.0"}, "host": M{"name": "web-01", "os": M{"type": "linux"}}, "ecs": M{"version": "8.0.0"}},
	}

	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			foldJSON := foldToJSON(t, m)
			reflectJSON := reflectToJSON(t, map[string]interface{}(m))
			assert.JSONEq(t, string(reflectJSON), string(foldJSON))
		})
	}
}

// TestFoldProducesValidJSON verifies output parses as valid JSON.
func TestFoldProducesValidJSON(t *testing.T) {
	m := M{
		"message": `hello "world"\nnewline`,
		"nested":  M{"key": "value"},
		"count":   42,
		"tags":    []string{"a", "b"},
	}
	output := foldToJSON(t, m)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(output, &parsed))
}

func foldToJSON(t *testing.T, m M) []byte {
	t.Helper()
	var buf bytes.Buffer
	v := sfjson.NewVisitor(&buf)
	require.NoError(t, m.Fold(structform.EnsureExtVisitor(v)))
	return buf.Bytes()
}

func reflectToJSON(t *testing.T, m map[string]interface{}) []byte {
	t.Helper()
	var buf bytes.Buffer
	v := sfjson.NewVisitor(&buf)
	require.NoError(t, gotype.Fold(m, v))
	return buf.Bytes()
}

func BenchmarkFold(b *testing.B) {
	m := M{
		"message": "log line",
		"agent":   M{"name": "filebeat", "version": "8.17.0", "type": "filebeat"},
		"host":    M{"name": "web-01", "os": M{"type": "linux", "platform": "ubuntu"}},
		"cloud":   M{"provider": "aws", "instance": M{"id": "i-abc"}},
		"log":     M{"file": M{"path": "/var/log/app.log"}, "offset": 12345},
		"ecs":     M{"version": "8.0.0"},
	}

	var buf bytes.Buffer
	v := sfjson.NewVisitor(&buf)
	ev := structform.EnsureExtVisitor(v)

	b.Run("fold", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			buf.Reset()
			_ = m.Fold(ev)
		}
	})

	b.Run("reflect", func(b *testing.B) {
		plain := map[string]interface{}(m)
		it, _ := gotype.NewIterator(v)
		b.ReportAllocs()
		for b.Loop() {
			buf.Reset()
			_ = it.Fold(plain)
		}
	})
}
