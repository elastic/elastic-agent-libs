package logp

import (
	"fmt"

	"go.uber.org/zap/zapcore"
)

// typedLoggerCore takes two cores and directs logs entries to one of them
// with the value of the field defined by the pair `key` and `value`
//
// If `entry[key] == value` the typedCore is used, otherwise the
// defaultCore  is used.
// WARNING: The level of both cores must always be the same!
// typedLoggerCore will only use the defaultCore level to decide
// whether to log an entry or not
type typedLoggerCore struct {
	typedCore   zapcore.Core
	defaultCore zapcore.Core
	value       string
	key         string
}

func (t *typedLoggerCore) Enabled(l zapcore.Level) bool {
	return t.defaultCore.Enabled(l)
}

func (t *typedLoggerCore) With(fields []zapcore.Field) zapcore.Core {
	t.defaultCore = t.defaultCore.With(fields)
	t.typedCore = t.typedCore.With(fields)
	return t
}

func (t *typedLoggerCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if t.defaultCore.Enabled(e.Level) {
		return ce.AddCore(e, t)
	}

	return ce
}

func (t *typedLoggerCore) Sync() error {
	defaultErr := t.defaultCore.Sync()
	typedErr := t.typedCore.Sync()

	if defaultErr != nil || typedErr != nil {
		return fmt.Errorf("error syncing logger. DefaultCore: '%w', typedCore: '%w'", defaultErr, typedErr)
	}

	return nil
}

func (t *typedLoggerCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	for _, f := range fields {
		if f.Key == t.key {
			if f.String == t.value {
				return t.typedCore.Write(e, fields)
			}
		}
	}

	return t.defaultCore.Write(e, fields)
}
