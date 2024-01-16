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

package logp

import (
	"encoding/json"
	"io/ioutil"
	golog "log"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLogger(t *testing.T) {
	exerciseLogger := func() {
		log := NewLogger("example")
		log.Info("some message")
		log.Infof("some message with parameter x=%v, y=%v", 1, 2)
		log.Infow("some message", "x", 1, "y", 2)
		log.Infow("some message", Int("x", 1))
		log.Infow("some message with namespaced args", Namespace("metrics"), "x", 1, "y", 1)
		log.Infow("", "empty_message", true)

		// Add context.
		log.With("x", 1, "y", 2).Warn("logger with context")

		someStruct := struct {
			X int `json:"x"`
			Y int `json:"y"`
		}{1, 2}
		log.Infow("some message with struct value", "metrics", someStruct)
	}

	err := TestingSetup()
	require.NoError(t, err)
	exerciseLogger()
	err = TestingSetup()
	require.NoError(t, err)
	exerciseLogger()
}

func TestLoggerLevel(t *testing.T) {
	if err := DevelopmentSetup(ToObserverOutput()); err != nil {
		t.Fatalf("cannot initialise logger on development mode: %+v", err)
	}

	const loggerName = "tester"
	logger := NewLogger(loggerName)

	logger.Debug("debug")
	logs := ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		assert.Equal(t, zap.DebugLevel, logs[0].Level)
		assert.Equal(t, loggerName, logs[0].LoggerName)
		assert.Equal(t, "debug", logs[0].Message)
	}

	logger.Info("info")
	logs = ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		assert.Equal(t, zap.InfoLevel, logs[0].Level)
		assert.Equal(t, loggerName, logs[0].LoggerName)
		assert.Equal(t, "info", logs[0].Message)
	}

	logger.Warn("warn")
	logs = ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		assert.Equal(t, zap.WarnLevel, logs[0].Level)
		assert.Equal(t, loggerName, logs[0].LoggerName)
		assert.Equal(t, "warn", logs[0].Message)
	}

	logger.Error("error")
	logs = ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		assert.Equal(t, zap.ErrorLevel, logs[0].Level)
		assert.Equal(t, loggerName, logs[0].LoggerName)
		assert.Equal(t, "error", logs[0].Message)
	}
}

func TestLoggerSetLevel(t *testing.T) {
	if err := DevelopmentSetup(ToObserverOutput()); err != nil {
		t.Fatal(err)
	}

	const loggerName = "tester"
	logger := NewLogger(loggerName)

	logger.Debug("debug")
	logs := ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		assert.Equal(t, zap.DebugLevel, logs[0].Level)
		assert.Equal(t, loggerName, logs[0].LoggerName)
		assert.Equal(t, "debug", logs[0].Message)
	}

	SetLevel(zap.InfoLevel)
	logger.Info("info")
	logs = ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		assert.Equal(t, zap.InfoLevel, logs[0].Level)
		assert.Equal(t, loggerName, logs[0].LoggerName)
		assert.Equal(t, "info", logs[0].Message)
	}

	logger.Debug("debug")
	logs = ObserverLogs().TakeAll()
	assert.Empty(t, logs, 1)
}

func TestL(t *testing.T) {
	if err := DevelopmentSetup(ToObserverOutput()); err != nil {
		t.Fatal(err)
	}

	L().Infow("infow", "rate", 2)
	logs := ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		log := logs[0]
		assert.Equal(t, zap.InfoLevel, log.Level)
		assert.Equal(t, "", log.LoggerName)
		assert.Equal(t, "infow", log.Message)
		assert.Contains(t, log.ContextMap(), "rate")
	}

	const loggerName = "tester"
	L().Named(loggerName).Warnf("warning %d", 1)
	logs = ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		log := logs[0]
		assert.Equal(t, zap.WarnLevel, log.Level)
		assert.Equal(t, loggerName, log.LoggerName)
		assert.Equal(t, "warning 1", log.Message)
	}
}

func TestDebugAllStdoutEnablesDefaultGoLogger(t *testing.T) {
	err := DevelopmentSetup(WithSelectors("*"))
	require.NoError(t, err)
	assert.Equal(t, _defaultGoLog, golog.Writer())

	err = DevelopmentSetup(WithSelectors("stdlog"))
	require.NoError(t, err)
	assert.Equal(t, _defaultGoLog, golog.Writer())

	err = DevelopmentSetup(WithSelectors("*", "stdlog"))
	require.NoError(t, err)
	assert.Equal(t, _defaultGoLog, golog.Writer())

	err = DevelopmentSetup(WithSelectors("other"))
	require.NoError(t, err)
	assert.Equal(t, ioutil.Discard, golog.Writer())
}

func TestNotDebugAllStdoutDisablesDefaultGoLogger(t *testing.T) {
	err := DevelopmentSetup(WithSelectors("*"), WithLevel(InfoLevel))
	require.NoError(t, err)
	assert.Equal(t, ioutil.Discard, golog.Writer())

	err = DevelopmentSetup(WithSelectors("stdlog"), WithLevel(InfoLevel))
	require.NoError(t, err)
	assert.Equal(t, ioutil.Discard, golog.Writer())

	err = DevelopmentSetup(WithSelectors("*", "stdlog"), WithLevel(InfoLevel))
	require.NoError(t, err)
	assert.Equal(t, ioutil.Discard, golog.Writer())

	err = DevelopmentSetup(WithSelectors("other"), WithLevel(InfoLevel))
	require.NoError(t, err)
	assert.Equal(t, ioutil.Discard, golog.Writer())
}

func TestLoggingECSFields(t *testing.T) {
	cfg := Config{
		Beat:        "beat1",
		Level:       DebugLevel,
		development: true,
		Files: FileConfig{
			Name: "beat1",
		},
	}
	ToObserverOutput()(&cfg)
	err := Configure(cfg)
	require.NoError(t, err)

	logger := NewLogger("tester")

	logger.Debug("debug")
	logs := ObserverLogs().TakeAll()
	if assert.Len(t, logs, 1) {
		if assert.Len(t, logs[0].Context, 1) {
			assert.Equal(t, "service.name", logs[0].Context[0].Key)
			assert.Equal(t, "beat1", logs[0].Context[0].String)
		}
	}
}

func TestWithFileOutput(t *testing.T) {
	var tempDir1, tempDir2 string
	// Because of the way logp and zap work, when the test finishes, the log
	// file is still open, this creates a problem on Windows because the
	// temporary directory cannot be removed if a file inside it is still
	// open.
	//
	// To circumvent this problem on Windows we use os.MkdirTemp
	// leaving it behind and delegating to the OS the responsibility
	// of cleaning it up (usually on restart).
	if runtime.GOOS == "windows" {
		var err error
		tempDir1, err = os.MkdirTemp("", t.Name()+"-*")
		if err != nil {
			t.Fatalf("could not create temporary directory: %s", err)
		}
		tempDir2, err = os.MkdirTemp("", t.Name()+"-*")
		if err != nil {
			t.Fatalf("could not create temporary directory: %s", err)
		}
	} else {
		// We have no problems on Linux and Darwin, so we can rely on t.TempDir
		// that will remove the files once the tests finishes.
		tempDir1 = t.TempDir()
		tempDir2 = t.TempDir()
	}

	expectedLogMessage := "this is a log message"
	expectedLogLogger := t.Name() + "-second"

	// We follow the same approach as on a Beat, first the logger
	// (always global) is configured and used, then we instantiate
	// a new one, secondLogger, and perform the tests on it.
	loggerCfg := DefaultConfig(DefaultEnvironment)
	loggerCfg.Beat = t.Name() + "-first"
	loggerCfg.ToFiles = true
	loggerCfg.ToStderr = false
	loggerCfg.Files.Name = "test-log-file-first"
	// We want a separate directory for this logger
	// and we don't need to inspect it.
	loggerCfg.Files.Path = tempDir1

	// Configures the global logger with the "default" log configuration.
	if err := Configure(loggerCfg); err != nil {
		t.Errorf("could not initialise logger: %s", err)
	}
	logger := L()

	// Create a log entry just to "test" the logger
	logger.Info("not the message we want")
	if err := logger.Sync(); err != nil {
		t.Fatalf("could not sync log file from fist logger: %s", err)
	}

	// Actually clones the logger and use the "WithFileOutput" function
	secondCfg := DefaultConfig(DefaultEnvironment)
	secondCfg.ToFiles = true
	secondCfg.ToStderr = false
	secondCfg.Files.Name = "test-log-file"
	secondCfg.Files.Path = tempDir2

	// We do not call Configure here as we do not want to affect
	// the global logger configuration
	secondLogger := NewLogger(t.Name() + "-second")
	secondLogger = secondLogger.WithOptions(zap.WrapCore(WithFileOutput(secondCfg)))
	secondLogger.Info(expectedLogMessage)
	if err := secondLogger.Sync(); err != nil {
		t.Fatalf("could not sync log file from second logger: %s", err)
	}

	// Writes again with the first logger to ensure it has not been affected
	// by the new configuration on the second logger.
	logger.Info("not the message we want")
	if err := logger.Sync(); err != nil {
		t.Fatalf("could not sync log file from fist logger: %s", err)
	}

	// Find the log file. The file name gets the date added, so we list the
	// directory and ensure there is only one file there.
	files, err := os.ReadDir(tempDir2)
	if err != nil {
		t.Fatalf("could not read temporary directory '%s': %s", tempDir2, err)
	}

	// If there is more than one file, list all files
	// and fail the test.
	if len(files) != 1 {
		t.Errorf("found %d files in '%s', there must be only one", len(files), tempDir2)
		t.Errorf("Files in '%s':", tempDir2)
		for _, f := range files {
			t.Error(f.Name())
		}
		t.FailNow()
	}

	logData, err := os.ReadFile(filepath.Join(tempDir2, files[0].Name()))
	if err != nil {
		t.Fatalf("could not read log file: %s", err)
	}

	logEntry := map[string]any{}
	if err := json.Unmarshal(logData, &logEntry); err != nil {
		t.Fatalf("could not read log entry as JSON. Log entry: '%s'", string(logData))
	}

	// Ensure a couple of fields exist
	if logEntry["log.logger"] != expectedLogLogger {
		t.Fatalf("expecting 'log.logger' to be '%s', got '%s' instead", expectedLogLogger, logEntry["log.logger"])
	}
	if logEntry["message"] != expectedLogMessage {
		t.Fatalf("expecting 'message' to be '%s, got '%s' instead", expectedLogMessage, logEntry["message"])
	}
}
