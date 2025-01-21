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
	"math"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoggerWithOptions(t *testing.T) {
	core1, observed1 := observer.New(zapcore.DebugLevel)
	core2, observed2 := observer.New(zapcore.DebugLevel)

	logger1 := NewLogger("bo", zap.WrapCore(func(in zapcore.Core) zapcore.Core {
		return zapcore.NewTee(in, core1)
	}))
	logger2 := logger1.WithOptions(zap.WrapCore(func(in zapcore.Core) zapcore.Core {
		return zapcore.NewTee(in, core2)
	}))

	logger1.Info("hello logger1")             // should just go to the first observer
	logger2.Info("hello logger1 and logger2") // should go to both observers

	observedEntries1 := observed1.All()
	require.Len(t, observedEntries1, 2)
	assert.Equal(t, "hello logger1", observedEntries1[0].Message)
	assert.Equal(t, "hello logger1 and logger2", observedEntries1[1].Message)

	observedEntries2 := observed2.All()
	require.Len(t, observedEntries2, 1)
	assert.Equal(t, "hello logger1 and logger2", observedEntries2[0].Message)
}

func TestNewInMemory(t *testing.T) {
	log, buff := NewInMemory("in_memory", ConsoleEncoderConfig())

	log.Debugw("a debug message", "debug_key", "debug_val")
	log.Infow("a info message", "info_key", "info_val")
	log.Warnw("a warn message", "warn_key", "warn_val")
	log.Errorw("an error message", "error_key", "error_val")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	assert.Len(t, logs, 4, "expected 4 log entries")

	assert.Contains(t, logs[0], "a debug message")
	assert.Contains(t, logs[0], "debug_key")
	assert.Contains(t, logs[0], "debug_val")

	assert.Contains(t, logs[1], "a info message")
	assert.Contains(t, logs[1], "info_key")
	assert.Contains(t, logs[1], "info_val")

	assert.Contains(t, logs[2], "a warn message")
	assert.Contains(t, logs[2], "warn_key")
	assert.Contains(t, logs[2], "warn_val")

	assert.Contains(t, logs[3], "an error message")
	assert.Contains(t, logs[3], "error_key")
	assert.Contains(t, logs[3], "error_val")
}

func TestThrottledLogger(t *testing.T) {
	l, buff := NewInMemory("in_memory", ConsoleEncoderConfig())

	log := l.Throttled(10 * time.Millisecond)

	log.Info("logged")
	log.Info("throttled")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 1, "expected 1 log entry")
	require.Contains(t, logs[0], "logged")

	time.Sleep(10 * time.Millisecond)

	log.Warn("logged")
	log.Info("throttled")
	log.Info("throttled")

	logs = strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 2, "expected 2 log entries")
	require.Contains(t, logs[1], "logged")
}

func TestSampledLogger(t *testing.T) {
	l, buff := NewInMemory("in_memory", ConsoleEncoderConfig())

	log := l.Sampled(2)

	log.Info("1")
	log.Info("2")
	log.Info("3")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 2, "expected 2 log entries")
	require.Contains(t, logs[0], "1")
	require.Contains(t, logs[1], "3")

	log.Info("4")
	log.Info("5")

	logs = strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 3, "expected 3 log entries")
	require.Contains(t, logs[2], "5")
}

func TestLimitedLogger(t *testing.T) {
	l, buff := NewInMemory("in_memory", ConsoleEncoderConfig())

	log := l.Limited(2)

	log.Info("1")
	log.Info("2")
	log.Info("3")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 2, "expected 2 log entries")
	require.Contains(t, logs[0], "1")
	require.Contains(t, logs[1], "2")

	log.Info("4")
	log.Info("5")

	logs = strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 2, "expected 2 log entries")
}

func TestSampledLimited(t *testing.T) {
	l, buff := NewInMemory("in_memory", ConsoleEncoderConfig())

	log := l.Sampled(2).Limited(3)

	log.Info("1")
	log.Info("2")
	log.Info("3")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 3, "expected 3 log entries")
	require.Contains(t, logs[0], "1")
	require.Contains(t, logs[1], "2")
	require.Contains(t, logs[2], "3")

	log.Info("4")
	log.Info("5")

	logs = strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 4, "expected 4 log entries")
	require.Contains(t, logs[3], "5")
}

func TestSampledThrottledLogger(t *testing.T) {
	l, buff := NewInMemory("in_memory", ConsoleEncoderConfig())

	log := l.Throttled(10 * time.Millisecond).Sampled(2)

	log.Info("logged")
	log.Info("throttled")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 1, "expected 1 log entry")
	require.Contains(t, logs[0], "logged")

	time.Sleep(10 * time.Millisecond)

	log.Warn("discarded by sampler")
	log.Info("throttled")

	logs = strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 2, "expected no new log entries")

	time.Sleep(10 * time.Millisecond)

	log.Warn("logged by sampler")
	log.Info("throttled")

	logs = strings.Split(strings.TrimSpace(buff.String()), "\n")
	require.Len(t, logs, 3, "expected 3 log entries")
	require.Contains(t, logs[2], "logged")
}

func BenchmarkLogger(b *testing.B) {
	l := newLogger(zap.NewNop(), "")

	b.Run("default", func(b *testing.B) {
		log := l.Named("default")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			log.Info("message")
		}
	})

	b.Run("sampled", func(b *testing.B) {
		log := l.Sampled(1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			log.Info("message")
		}
	})

	b.Run("throttled", func(b *testing.B) {
		log := l.Throttled(1 * time.Nanosecond)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			log.Info("message")
		}
	})

	b.Run("limited", func(b *testing.B) {
		log := l.Limited(math.MaxInt)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			log.Info("message")
		}
	})
}

func BenchmarkConcurrentLoggerSynthetic(b *testing.B) {
	l := newLogger(zap.NewNop(), "")

	b.Run("default", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Named("default")
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
	})

	b.Run("sampled", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Sampled(1)
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
		group.Wait()
	})

	b.Run("throttled", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Throttled(1 * time.Nanosecond)
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
		group.Wait()
	})

	b.Run("limited", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Limited(math.MaxInt)
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
		group.Wait()
	})
}

func BenchmarkConcurrentLoggerRealistic(b *testing.B) {
	l := newLogger(zap.NewNop(), "")

	b.Run("default", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Named("default")
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
	})

	b.Run("sampled-every-4", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Sampled(4)
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
		group.Wait()
	})

	b.Run("throttled-1-per-second", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Throttled(1 * time.Second)
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
		group.Wait()
	})

	b.Run("limited-first-10", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Limited(10)
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
		group.Wait()
	})

	b.Run("sampled-1-out-of-2-limited-first-10-throttled-1-per-second", func(b *testing.B) {
		var group sync.WaitGroup
		log := l.Limited(10).Sampled(2).Throttled(1 * time.Second)
		b.ResetTimer()
		for i := runtime.NumCPU(); i > 0; i-- {
			group.Add(1)
			go func() {
				for i := 0; i < b.N; i++ {
					log.Info("message")
				}
				defer group.Done()
			}()
		}
		group.Wait()
	})
}
