package logptest

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestNewFileLogger(t *testing.T) {
	logger := NewFileLogger(t, "")
	logger.Debug("foo")

	assertLogFormat(t, logger.logFile.Name())

	t.Run("FindInLogs", func(t *testing.T) {
		found, err := logger.FindInLogs("foo")
		if err != nil {
			t.Fatalf("did not expect an error from 'FindInLogs': %s", err)
		}

		if !found {
			t.Fatal("expecing 'FindInLogs' to return true")
		}
	})

	t.Run("LogContains", func(t *testing.T) {
		// Log again, because we track offset
		logger.Debug("foo")
		// Call it and expect the test not to fail
		logger.LogContains(t, "foo")
	})

	t.Run("WaitLogContains", func(t *testing.T) {
		// Log again, because we track offset
		logger.Debug("foo")
		// Call it and expect the test not to fail
		logger.WaitLogsContains(t, "foo", 200*time.Millisecond)
	})

	t.Run("ResetOffset", func(t *testing.T) {
		logger.ResetOffset()

		// We logged "foo" 3 time, so we should find it 3 times in a row.
		for range 3 {
			found, err := logger.FindInLogs("foo")
			if err != nil {
				t.Fatalf("did not expect an error from 'FindInLogs': %s", err)
			}

			if !found {
				t.Fatal("expecing 'FindInLogs' to return true")
			}
		}
	})
}

func TestLoggerFileIsRemoved(t *testing.T) {
	toBeDeletedLogFile := ""
	// Use a subtest so it can finish and succeed before
	// we check if the log file has been removed
	t.Run("log file is removed", func(t *testing.T) {
		logger := NewFileLogger(t, "")
		logger.Info("foo")
		toBeDeletedLogFile = logger.logFile.Name()
	})

	_, err := os.Stat(toBeDeletedLogFile)
	if !errors.Is(err, os.ErrNotExist) {
		t.Error("the log file must be removed after a test passes")
	}
}

func assertLogFormat(t *testing.T, path string) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("cannot open log file: %s", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		entry := struct {
			Timestamp string `json:"@timestamp"`
			LogLevel  string `json:"log.level"`
			Message   string `json:"message"`
		}{}

		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			t.Fatalf("%q is not a ndjson file: %s", path, err)
		}

		// ensure the basic fileds are populated
		if entry.Timestamp == "" {
			t.Error("'@timestamp' cannot be empty/zero value")
		}

		if entry.LogLevel == "" {
			t.Error("'log.level' cannot be emtpy")
		}

		if entry.Message == "" {
			t.Error("message cannot be empty")
		}
	}
}
