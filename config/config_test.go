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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
)

func TestUnmarshalFromConfmap(t *testing.T) {
	t.Run("flat key-value pairs", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"host": "localhost",
			"port": 9200,
		})

		c := NewConfig()
		require.NoError(t, c.Unmarshal(conf))

		host, err := c.String("host", -1)
		require.NoError(t, err)
		assert.Equal(t, "localhost", host)

		port, err := c.Int("port", -1)
		require.NoError(t, err)
		assert.Equal(t, int64(9200), port)
	})

	t.Run("nested configuration", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"output": map[string]any{
				"elasticsearch": map[string]any{
					"hosts": []any{"https://es:9200"},
				},
			},
		})

		c := NewConfig()
		require.NoError(t, c.Unmarshal(conf))

		type esConfig struct {
			Hosts []string `config:"hosts"`
		}
		type outputConfig struct {
			Elasticsearch esConfig `config:"elasticsearch"`
		}
		type cfg struct {
			Output outputConfig `config:"output"`
		}

		var result cfg
		require.NoError(t, c.Unpack(&result))
		assert.Equal(t, []string{"https://es:9200"}, result.Output.Elasticsearch.Hosts)
	})

	t.Run("empty confmap", func(t *testing.T) {
		conf := confmap.New()

		c := NewConfig()
		require.NoError(t, c.Unmarshal(conf))
		assert.Empty(t, c.GetFields())
	})

	t.Run("merges into existing config", func(t *testing.T) {
		existing, err := NewConfigFrom(map[string]interface{}{
			"timeout": 30,
			"enabled": true,
		})
		require.NoError(t, err)

		conf := confmap.NewFromStringMap(map[string]any{
			"workers": 4,
		})
		require.NoError(t, existing.Unmarshal(conf))

		type cfg struct {
			Timeout int  `config:"timeout"`
			Enabled bool `config:"enabled"`
			Workers int  `config:"workers"`
		}
		var result cfg
		require.NoError(t, existing.Unpack(&result))
		assert.Equal(t, 30, result.Timeout)
		assert.True(t, result.Enabled)
		assert.Equal(t, 4, result.Workers)
	})

	t.Run("later values overwrite earlier ones on merge", func(t *testing.T) {
		existing, err := NewConfigFrom(map[string]interface{}{
			"level": "info",
		})
		require.NoError(t, err)

		conf := confmap.NewFromStringMap(map[string]any{
			"level": "debug",
		})
		require.NoError(t, existing.Unmarshal(conf))

		level, err := existing.String("level", -1)
		require.NoError(t, err)
		assert.Equal(t, "debug", level)
	})

	t.Run("boolean values", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"enabled": true,
		})

		c := NewConfig()
		require.NoError(t, c.Unmarshal(conf))

		enabled, err := c.Bool("enabled", -1)
		require.NoError(t, err)
		assert.True(t, enabled)
	})
}
