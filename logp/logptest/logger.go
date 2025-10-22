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

package logptest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"
)

// Logger wraps a *logp.Logger and makes it more suitable for tests.
// Key features:
//   - All logs are saved on a single temporary log file
//   - On failures, the log file is kept and its path printed
//   - Methods to search and wait for log entries are provided,
//     they keep track of the offset, ensuring ordering when
//     when searching for logs
type Logger struct {
	*logp.Logger
	t       *testing.T
	logFile *os.File
	offset  int64
}

// NewFileLogger returns a logger that logs to a file and has methods
// to search in the logs.
// The *logp.Logger is embedded into it, so [Logger] is a drop-in
// replacement for a *logp.Logger, or the logger can be accessed via
// [Logger.Logger]
func NewFileLogger(t *testing.T) *Logger {
	encoderConfig := ecszap.ECSCompatibleEncoderConfig(zapcore.EncoderConfig{})
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewJSONEncoder(encoderConfig)

	f, err := os.CreateTemp("", "testing-logger-*.log")
	if err != nil {
		t.Fatalf("cannot create log file: %s", err)
	}

	core := zapcore.NewCore(encoder, zapcore.AddSync(f), zap.DebugLevel)

	tl := &Logger{
		t:       t,
		logFile: f,
	}

	t.Cleanup(func() {
		// Sync the core, the file, then close the file
		if err := core.Sync(); err != nil {
			t.Logf("cannot sync zap core: %s", err)
		}

		if err := f.Sync(); err != nil {
			t.Logf("cannot sync log file: %s", err)
		}

		if err := f.Close(); err != nil {
			t.Logf("cannot close log file: %s", err)
		}

		// If the test failed, print the log file location,
		// otherwise remove it.
		if t.Failed() {
			t.Logf("Full logs written to %s", f.Name())
			return
		}

		if err := os.Remove(f.Name()); err != nil {
			t.Logf("could not remove temporary log file: %s", err)
		}
	})

	logger := logp.NewLogger(
		"",
		zap.WrapCore(func(in zapcore.Core) zapcore.Core {
			return core
		}))

	tl.Logger = logger

	return tl
}

// WaitLogsContains waits for the specified string s to be present in the logs within
// the given timeout duration and fails the test if s is not found.
// It keeps track of the log file offset, reading only new lines. Each
// subsequent call to WaitLogsContains will only check logs not yet evaluated.
// msgAndArgs should be a format string and arguments that will be printed
// if the logs are not found, providing additional context for debugging.
func (l *Logger) WaitLogsContains(s string, timeout time.Duration, msgAndArgs ...any) {
	l.t.Helper()
	require.EventuallyWithT(
		l.t,
		func(c *assert.CollectT) {
			found, err := l.logContains(s)
			if err != nil {
				c.Errorf("cannot check the log file: %s", err)
				return
			}

			if !found {
				c.Errorf("did not find '%s' in the logs", s)
			}
		},
		timeout,
		100*time.Millisecond,
		msgAndArgs...)
}

// logContains searches for str in the log file keeping track of the offset.
// If there is any issue reading the log file, then t.Fatalf is called,
// if str is not present in the logs, t.Fatalf is called.
func (l *Logger) LogContains(str string) {
	l.t.Helper()
	found, err := l.logContains(str)
	if err != nil {
		l.t.Fatalf("cannot read log file: %s", err)
	}

	if !found {
		l.t.Fatalf("'%s' not found in logs", str)
	}
}

// logContains searches for str in the log file keeping track of the offset.
// It returns true if str is found in the logs. If there are any errors,
// it returns false and the error
func (l *Logger) logContains(str string) (bool, error) {
	// Open the file again so we can seek and not interfere with
	// the logger writing to it.
	f, err := os.Open(l.logFile.Name())
	if err != nil {
		return false, fmt.Errorf("cannot open log file for reading: %w", err)
	}

	if _, err := f.Seek(l.offset, io.SeekStart); err != nil {
		return false, fmt.Errorf("cannot seek log file: %w", err)
	}

	r := bufio.NewReader(f)
	for {
		data, err := r.ReadBytes('\n')
		line := string(data)
		l.offset += int64(len(data))

		if err != nil {
			if !errors.Is(err, io.EOF) {
				return false, fmt.Errorf("error reading log file '%s': %w", l.logFile.Name(), err)
			}
			break
		}

		if strings.Contains(line, str) {
			return true, nil
		}
	}

	return false, nil
}
