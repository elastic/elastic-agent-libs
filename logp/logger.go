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
	"bytes"
	"fmt"
	"io"

	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogOption configures a Logger.
type LogOption = zap.Option

// Logger logs messages to the configured output.
type Logger struct {
	logger *zap.Logger
	sugar  *zap.SugaredLogger
}

func newLogger(rootLogger *zap.Logger, selector string, options ...LogOption) *Logger {
	log := rootLogger.
		WithOptions(zap.AddCallerSkip(1)).
		WithOptions(options...).
		Named(selector)
	return &Logger{log, log.Sugar()}
}

// NewLogger returns a new Logger labeled with the name of the selector. This
// should never be used from any global contexts, otherwise you will receive a
// no-op Logger. This is because the logp package needs to be initialized first.
// Instead create new Logger instance that your object reuses. Or if you need to
// log from a static context then you may use logp.L().Infow(), for example.
func NewLogger(selector string, options ...LogOption) *Logger {
	return newLogger(loadLogger().rootLogger, selector, options...)
}

// NewNopLogger returns a no-op logger
func NewNopLogger() *Logger {
	logger := zap.NewNop()
	return &Logger{logger, logger.Sugar()}
}

// NewProductionLogger returns a production suitable logp.Logger
func NewProductionLogger(selector string, options ...LogOption) (*Logger, error) {
	log, err := zap.NewProduction(options...)
	log = log.Named(selector)
	if err != nil {
		return nil, err
	}
	return &Logger{log, log.Sugar()}, nil
}

// NewDevelopmentLogger returns a development suitable logp.Logger
func NewDevelopmentLogger(selector string, options ...LogOption) (*Logger, error) {
	options = append([]LogOption{zap.AddCallerSkip(1)}, options...)
	log, err := zap.NewDevelopment(options...)
	log = log.Named(selector)
	if err != nil {
		return nil, err
	}
	return &Logger{log, log.Sugar()}, nil
}

// NewInMemory returns a new in-memory logger along with the buffer to which it
// logs. It's goroutine safe, but operating directly on the returned buffer is not.
// This logger is primary intended for short and simple use-cases such as printing
// the full logs only when an operation fails.
// encCfg configures the log format, use logp.ConsoleEncoderConfig for console
// format, logp.JSONEncoderConfig for JSON or any other valid zapcore.EncoderConfig.
//
// Deprecated: Prefer using localized loggers. Use logp.NewInMemoryLocal.
func NewInMemory(selector string, encCfg zapcore.EncoderConfig) (*Logger, *bytes.Buffer) {
	buff := bytes.Buffer{}

	encoderConfig := ecszap.ECSCompatibleEncoderConfig(encCfg)
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewConsoleEncoder(encoderConfig)

	core := zapcore.NewCore(
		encoder,
		zapcore.Lock(zapcore.AddSync(&buff)),
		zap.NewAtomicLevelAt(zap.DebugLevel))
	ecszap.ECSCompatibleEncoderConfig(ConsoleEncoderConfig())

	logger := NewLogger(
		selector,
		zap.WrapCore(func(in zapcore.Core) zapcore.Core {
			return core
		}))

	return logger, &buff
}

// NewInMemory returns a new in-memory logger along with the buffer to which it
// logs. It's goroutine safe, but operating directly on the returned buffer is not.
// This logger is primary intended for short and simple use-cases such as printing
// the full logs only when an operation fails.
// encCfg configures the log format, use logp.ConsoleEncoderConfig for console
// format, logp.JSONEncoderConfig for JSON or any other valid zapcore.EncoderConfig.
func NewInMemoryLocal(selector string, encCfg zapcore.EncoderConfig) (*Logger, *bytes.Buffer) {
	buff := bytes.Buffer{}

	encoderConfig := ecszap.ECSCompatibleEncoderConfig(encCfg)
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewConsoleEncoder(encoderConfig)

	core := zapcore.NewCore(
		encoder,
		zapcore.Lock(zapcore.AddSync(&buff)),
		zap.NewAtomicLevelAt(zap.DebugLevel))
	ecszap.ECSCompatibleEncoderConfig(ConsoleEncoderConfig())

	logger, _ := NewDevelopmentLogger(
		selector,
		zap.WrapCore(func(in zapcore.Core) zapcore.Core {
			return core
		}))

	return logger, &buff
}

// WithOptions returns a clone of l with options applied.
func (l *Logger) WithOptions(options ...LogOption) *Logger {
	cloned := l.logger.WithOptions(options...)
	return &Logger{cloned, cloned.Sugar()}
}

// With creates a child logger and adds structured context to it. Fields added
// to the child don't affect the parent, and vice versa.
func (l *Logger) With(args ...interface{}) *Logger {
	sugar := l.sugar.With(args...)
	return &Logger{sugar.Desugar(), sugar}
}

// Named adds a new path segment to the logger's name. Segments are joined by
// periods.
func (l *Logger) Named(name string) *Logger {
	logger := l.logger.Named(name)
	return &Logger{logger, logger.Sugar()}
}

// Sprint

// Debug uses fmt.Sprint to construct and log a message.
func (l *Logger) Debug(args ...interface{}) {
	l.sugar.Debug(args...)
}

// Info uses fmt.Sprint to construct and log a message.
func (l *Logger) Info(args ...interface{}) {
	l.sugar.Info(args...)
}

// Warn uses fmt.Sprint to construct and log a message.
func (l *Logger) Warn(args ...interface{}) {
	l.sugar.Warn(args...)
}

// Error uses fmt.Sprint to construct and log a message.
func (l *Logger) Error(args ...interface{}) {
	l.sugar.Error(args...)
}

// Fatal uses fmt.Sprint to construct and log a message, then calls os.Exit(1).
func (l *Logger) Fatal(args ...interface{}) {
	l.sugar.Fatal(args...)
}

// Panic uses fmt.Sprint to construct and log a message, then panics.
func (l *Logger) Panic(args ...interface{}) {
	l.sugar.Panic(args...)
}

// DPanic uses fmt.Sprint to construct and log a message. In development, the
// logger then panics.
func (l *Logger) DPanic(args ...interface{}) {
	l.sugar.DPanic(args...)
}

// IsDebug checks to see if the given logger is Debug enabled.
func (l *Logger) IsDebug() bool {
	return l.logger.Check(zapcore.DebugLevel, "") != nil
}

// Sprintf

// Debugf uses fmt.Sprintf to construct and log a message.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.sugar.Debugf(format, args...)
}

// Infof uses fmt.Sprintf to log a templated message.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.sugar.Infof(format, args...)
}

// Warnf uses fmt.Sprintf to log a templated message.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.sugar.Warnf(format, args...)
}

// Errorf uses fmt.Sprintf to log a templated message.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.sugar.Errorf(format, args...)
}

// Fatalf uses fmt.Sprintf to log a templated message, then calls os.Exit(1).
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.sugar.Fatalf(format, args...)
}

// Panicf uses fmt.Sprintf to log a templated message, then panics.
func (l *Logger) Panicf(format string, args ...interface{}) {
	l.sugar.Panicf(format, args...)
}

// DPanicf uses fmt.Sprintf to log a templated message. In development, the
// logger then panics.
func (l *Logger) DPanicf(format string, args ...interface{}) {
	l.sugar.DPanicf(format, args...)
}

// With context (reflection based)

// Debugw logs a message with some additional context. The additional context
// is added in the form of key-value pairs. The optimal way to write the value
// to the log message will be inferred by the value's type. To explicitly
// specify a type you can pass a Field such as logp.Stringer.
func (l *Logger) Debugw(msg string, keysAndValues ...interface{}) {
	l.sugar.Debugw(msg, keysAndValues...)
}

// Infow logs a message with some additional context. The additional context
// is added in the form of key-value pairs. The optimal way to write the value
// to the log message will be inferred by the value's type. To explicitly
// specify a type you can pass a Field such as logp.Stringer.
func (l *Logger) Infow(msg string, keysAndValues ...interface{}) {
	l.sugar.Infow(msg, keysAndValues...)
}

// Warnw logs a message with some additional context. The additional context
// is added in the form of key-value pairs. The optimal way to write the value
// to the log message will be inferred by the value's type. To explicitly
// specify a type you can pass a Field such as logp.Stringer.
func (l *Logger) Warnw(msg string, keysAndValues ...interface{}) {
	l.sugar.Warnw(msg, keysAndValues...)
}

// Errorw logs a message with some additional context. The additional context
// is added in the form of key-value pairs. The optimal way to write the value
// to the log message will be inferred by the value's type. To explicitly
// specify a type you can pass a Field such as logp.Stringer.
func (l *Logger) Errorw(msg string, keysAndValues ...interface{}) {
	l.sugar.Errorw(msg, keysAndValues...)
}

// Fatalw logs a message with some additional context, then calls os.Exit(1).
// The additional context is added in the form of key-value pairs. The optimal
// way to write the value to the log message will be inferred by the value's
// type. To explicitly specify a type you can pass a Field such as
// logp.Stringer.
func (l *Logger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.sugar.Fatalw(msg, keysAndValues...)
}

// Panicw logs a message with some additional context, then panics. The
// additional context is added in the form of key-value pairs. The optimal way
// to write the value to the log message will be inferred by the value's type.
// To explicitly specify a type you can pass a Field such as logp.Stringer.
func (l *Logger) Panicw(msg string, keysAndValues ...interface{}) {
	l.sugar.Panicw(msg, keysAndValues...)
}

// DPanicw logs a message with some additional context. The logger panics only
// in Development mode.  The additional context is added in the form of
// key-value pairs. The optimal way to write the value to the log message will
// be inferred by the value's type. To explicitly specify a type you can pass a
// Field such as logp.Stringer.
func (l *Logger) DPanicw(msg string, keysAndValues ...interface{}) {
	l.sugar.DPanicw(msg, keysAndValues...)
}

// Recover stops a panicking goroutine and logs an Error.
func (l *Logger) Recover(msg string) {
	if r := recover(); r != nil {
		msg := fmt.Sprintf("%s. Recovering, but please report this.", msg)
		l.Error(msg, zap.Any("panic", r), zap.Stack("stack"))
	}
}

// Sync syncs the logger.
func (l *Logger) Sync() error {
	return l.logger.Sync()
}

// Core returns the backend zapcore.Core for the logger.
func (l *Logger) Core() zapcore.Core {
	return l.logger.Core()
}

// Close closes the underlying logger core/writer.
func (l *Logger) Close() error {
	if closer, ok := l.logger.Core().(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// L returns an unnamed global logger.
func L() *Logger {
	return loadLogger().logger
}
