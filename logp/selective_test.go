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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasSelector(t *testing.T) {
	err := DevelopmentSetup(WithSelectors("*", "config"))
	require.NoError(t, err)
	assert.True(t, HasSelector("config"))
	assert.False(t, HasSelector("publish"))
}

func TestLoggerSelectors(t *testing.T) {
	if err := DevelopmentSetup(WithSelectors("good", " padded "), ToObserverOutput()); err != nil {
		t.Fatal(err)
	}

	assert.True(t, HasSelector("padded"))

	good := NewLogger("good")
	bad := NewLogger("bad")

	good.Debug("is logged")
	logs := ObserverLogs().TakeAll()
	assert.Len(t, logs, 1)

	// Selectors only apply to debug level logs.
	bad.Debug("not logged")
	logs = ObserverLogs().TakeAll()
	assert.Len(t, logs, 0)

	bad.Info("is also logged")
	logs = ObserverLogs().TakeAll()
	assert.Len(t, logs, 1)
}

func TestLoggerBlockList(t *testing.T) {
	if err := DevelopmentSetup(WithBlockSelectors("tooVerbose", " sensitiveInformation "), ToObserverOutput()); err != nil {
		t.Fatal(err)
	}

	require.True(t, IsBlocked("tooVerbose"))
	require.True(t, IsBlocked("sensitiveInformation"))

	doesNotLog := NewLogger("tooVerbose")
	doesNotLog2 := NewLogger("sensitiveInformation")
	willLog := NewLogger("notVerbose")

	doesNotLog.Debug("is not logged")
	logs := ObserverLogs().TakeAll()
	assert.Len(t, logs, 0)

	doesNotLog2.Debug("is not logged")
	logs = ObserverLogs().TakeAll()
	assert.Len(t, logs, 0)

	// Selectors only apply to debug level logs.
	willLog.Debug("is logged")
	logs = ObserverLogs().TakeAll()
	assert.Len(t, logs, 1)

	willLog.Info("is also logged")
	logs = ObserverLogs().TakeAll()
	assert.Len(t, logs, 1)
}
