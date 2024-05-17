//go:build windows

package logp

import (
	"io"
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestEventLogOutputCanBeClosed(t *testing.T) {
	cfg := DefaultConfig(DefaultEnvironment)
	cfg.ToFiles = true

	eventLog, err := makeEventLogOutput(cfg, zapcore.DebugLevel)
	if err != nil {
		t.Fatalf("cannot create eventLog output: %s", err)
	}

	if _, ok := eventLog.(io.Closer); !ok {
		t.Fatal("the EventLog Output does not implement io.Closer")
	}
}
