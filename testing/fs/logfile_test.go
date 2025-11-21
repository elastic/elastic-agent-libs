package fs

import (
	"sync"
	"testing"
	"time"
)

func TestLogFile(t *testing.T) {
	msg := "it works!"
	lf := NewLogFile(t, "", "")
	if _, err := lf.WriteString(msg + "\n"); err != nil {
		t.Fatalf("cannot write to file: %s", err)
	}

	// Ensure we can find the string we wrote
	lf.LogContains(t, msg)

	// calling FindInLogs will fail because it tracks the offset
	found, err := lf.FindInLogs(msg)
	if err != nil {
		t.Fatalf("cannot search in log file: %s", err)
	}

	if found {
		t.Error("'FindInLogs' must keep track of offset, it should have returned false")
	}

	lf.ResetOffset()
	found, err = lf.FindInLogs(msg)
	if err != nil {
		t.Fatalf("cannot search in log file: %s", err)
	}

	if !found {
		t.Error("offset was reset, 'FindInLogs' must succeed")
	}

	msg2 := "second message"
	wg := sync.WaitGroup{}
	wg.Add(1)

	wgRunning := sync.WaitGroup{}
	wgRunning.Add(1)
	go func() {
		wgRunning.Done()
		lf.WaitLogsContains(t, msg2, 5*time.Second, "did not find msg2")
		wg.Done()
	}()

	// Ensure the goroutine that calls WaitLogsContains is running
	wgRunning.Wait()

	// Write to the file
	if _, err := lf.WriteString(msg2 + "\n"); err != nil {
		t.Fatalf("cannot write to file: %s", err)
	}

	// Ensure the goroutine finishes without failing the tests
	wg.Wait()
	if t.Failed() {
		t.Error("WaitLogsContains should have succeeded")
	}
}
