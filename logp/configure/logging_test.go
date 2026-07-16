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

package configure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

func TestLoggerOutputEnvironment(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         *config.C
		expectedCfg *logp.Config
		env         logp.Environment
	}{
		{
			name: "no logging config - output should be to_files",
			cfg:  config.MustNewConfigFrom(map[string]interface{}{}),
			expectedCfg: &logp.Config{
				ToFiles:  true,
				ToStderr: false,
			},
			env: logp.DefaultEnvironment,
		},
		{
			name: "output should be to_files",
			cfg: config.MustNewConfigFrom(map[string]interface{}{
				"to_files": true,
			}),
			expectedCfg: &logp.Config{
				ToFiles:  true,
				ToStderr: false,
			},
			env: logp.DefaultEnvironment,
		},
		{
			name: "output should be to_stderr",
			cfg: config.MustNewConfigFrom(map[string]interface{}{
				"to_stderr": true,
			}),
			expectedCfg: &logp.Config{
				ToFiles:  false,
				ToStderr: true,
			},
			env: logp.DefaultEnvironment,
		},
		{
			name: "output should be to_stderr - systemd",
			cfg:  config.MustNewConfigFrom(map[string]interface{}{}),
			expectedCfg: &logp.Config{
				ToFiles:  false,
				ToStderr: true,
			},
			env: logp.SystemdEnvironment,
		},
		{
			name: "output should be to_stderr - systemd",
			cfg: config.MustNewConfigFrom(map[string]interface{}{
				"to_stderr": true,
			}),
			expectedCfg: &logp.Config{
				ToFiles:  false,
				ToStderr: true,
			},
			env: logp.SystemdEnvironment,
		},
		{
			name: "output should be to_files - systemd",
			cfg: config.MustNewConfigFrom(map[string]interface{}{
				"to_files": true,
			}),
			expectedCfg: &logp.Config{
				ToFiles:  true,
				ToStderr: false,
			},
			env: logp.SystemdEnvironment,
		},
	}
	for _, tc := range testCases {
		t.Run("test environment", func(t *testing.T) {
			environment = tc.env
			defer func() {
				environment = logp.DefaultEnvironment
			}()
			config := logp.DefaultConfig(environment)
			err := tc.cfg.Unpack(&config)
			require.NoError(t, err, "unpacking config should not fail")
			applyFlags(&config)
			require.Equal(t, tc.expectedCfg.ToFiles, config.ToFiles)
			require.Equal(t, tc.expectedCfg.ToStderr, config.ToStderr)
		})
	}
}

func TestLoggingWithTypedOutputsLocal(t *testing.T) {
	t.Run("returns a working logger", func(t *testing.T) {
		obsCore, obsLogs := observer.New(zapcore.InfoLevel)

		logger, err := LoggingWithTypedOutputsLocal(
			"testbeat", noFileConfig(t), nil,
			logp.TypeKey, logp.EventType,
			obsCore,
		)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Debug("suppressed")
		assert.Equal(t, 0, obsLogs.Len(), "Debug must be suppressed at InfoLevel")

		logger.Info("visible")
		assert.Equal(t, 1, obsLogs.Len(), "Info must reach the observer")
	})
}

func TestLoggingWithTypedOutputsLocalWithLevel(t *testing.T) {
	t.Run("returns a working logger", func(t *testing.T) {
		al := zap.NewAtomicLevelAt(zap.InfoLevel)
		obsCore, obsLogs := observer.New(al)

		logger, err := LoggingWithTypedOutputsLocalWithLevel(
			"testbeat", noFileConfig(t), nil,
			logp.TypeKey, logp.EventType,
			al, obsCore,
		)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Debug("suppressed")
		assert.Equal(t, 0, obsLogs.Len(), "Debug must be suppressed at InfoLevel")

		logger.Info("visible")
		assert.Equal(t, 1, obsLogs.Len(), "Info must reach the observer")
	})

	t.Run("level can be changed at runtime", func(t *testing.T) {
		al := zap.NewAtomicLevelAt(zap.InfoLevel)
		obsCore, obsLogs := observer.New(al)

		logger, err := LoggingWithTypedOutputsLocalWithLevel(
			"testbeat", noFileConfig(t), nil,
			logp.TypeKey, logp.EventType,
			al, obsCore,
		)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Debug("suppressed")
		assert.Equal(t, 0, obsLogs.Len(), "Debug must be suppressed at InfoLevel")

		logger.Info("visible")
		assert.Equal(t, 1, obsLogs.Len(), "Info must be captured at InfoLevel")

		al.SetLevel(zap.DebugLevel)
		logger.Debug("visible")
		assert.Equal(t, 2, obsLogs.Len(), "Debug must be captured after lowering to DebugLevel")
	})
}

func TestLoggingWithTypedOutputsNonGlobal(t *testing.T) {
	t.Run("returns a working logger", func(t *testing.T) {
		obsCore, obsLogs := observer.New(zapcore.InfoLevel)

		logger, err := LoggingWithTypedOutputsNonGlobal(
			"testbeat", noFileConfig(t), nil,
			logp.TypeKey, logp.EventType,
			obsCore,
		)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Debug("suppressed")
		assert.Equal(t, 0, obsLogs.Len(), "Debug must be suppressed at InfoLevel")

		logger.Info("visible")
		assert.Equal(t, 1, obsLogs.Len(), "Info must reach the observer")
	})
}

func TestLoggingWithTypedOutputsNonGlobalWithLevel(t *testing.T) {
	t.Run("returns a working logger", func(t *testing.T) {
		al := zap.NewAtomicLevelAt(zap.InfoLevel)
		obsCore, obsLogs := observer.New(al)

		logger, err := LoggingWithTypedOutputsNonGlobalWithLevel(
			"testbeat", noFileConfig(t), nil,
			logp.TypeKey, logp.EventType,
			al, obsCore,
		)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Debug("suppressed")
		assert.Equal(t, 0, obsLogs.Len(), "Debug must be suppressed at InfoLevel")

		logger.Info("visible")
		assert.Equal(t, 1, obsLogs.Len(), "Info must reach the observer")
	})

	t.Run("level can be changed at runtime", func(t *testing.T) {
		al := zap.NewAtomicLevelAt(zap.InfoLevel)
		obsCore, obsLogs := observer.New(al)

		logger, err := LoggingWithTypedOutputsNonGlobalWithLevel(
			"testbeat", noFileConfig(t), nil,
			logp.TypeKey, logp.EventType,
			al, obsCore,
		)
		require.NoError(t, err)
		require.NotNil(t, logger)

		logger.Debug("suppressed")
		assert.Equal(t, 0, obsLogs.Len(), "Debug must be suppressed at InfoLevel")

		logger.Info("visible")
		assert.Equal(t, 1, obsLogs.Len(), "Info must be captured at InfoLevel")

		al.SetLevel(zap.DebugLevel)
		logger.Debug("visible")
		assert.Equal(t, 2, obsLogs.Len(), "Debug must be captured after lowering to DebugLevel")
	})
}

func noFileConfig(t *testing.T) *config.C {
	t.Helper()
	return config.MustNewConfigFrom(map[string]interface{}{
		"to_files":  false,
		"to_stderr": false,
	})
}
