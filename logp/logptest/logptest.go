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
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent-libs/logp"
)

// NewTestingLogger Just calls [NewFileLogger], the log if is placed in the
// the folder returned by [os.TempDir].
//
// DEPRECATED: The logger returned by [NewTestingLogger] can panic if it is
// used after the test has ended. Use [NewFileLogger] instead.
func NewTestingLogger(t testing.TB, selector string, options ...logp.LogOption) *logp.Logger {
	l := NewFileLogger(t, "")
	return l.Logger
}

// NewTestingLoggerWithObserver returns a testing suitable logp.Logger that uses the
// [testing.T] as the logger output and an observer.
func NewTestingLoggerWithObserver(t testing.TB, selector string) (*logp.Logger, *observer.ObservedLogs) {
	observedCore, observedLogs := observer.New(zapcore.DebugLevel)
	logger := NewTestingLogger(t, selector, zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return observedCore
	}))

	return logger, observedLogs
}
