package main

import (
	"errors"
	"strings"
	"testing"
)

// failingWriter fails after letting n bytes through, which is what a redirected
// output on a full disk does: the first line lands and the next does not.
type failingWriter struct {
	remaining int
	written   strings.Builder

	// next is the error the following write reports, so a test can tell a
	// remembered failure from a freshly produced one.
	next error
}

var (
	errDiskFull   = errors.New("no space left on device")
	errBrokenPipe = errors.New("broken pipe")
)

func (f *failingWriter) fail() error {
	if f.next != nil {
		return f.next
	}
	return errDiskFull
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, f.fail()
	}
	if len(p) > f.remaining {
		n, _ := f.written.Write(p[:f.remaining])
		f.remaining = 0
		return n, f.fail()
	}
	f.remaining -= len(p)
	return f.written.Write(p)
}

// TestCheckedWriterRemembersTheFirstFailure is the guard on printing a
// credential that cannot be printed again.
//
// A bootstrap token is minted, stored as a digest and audited before it reaches
// the output. If the write is discarded, the deployment has a full
// administrator nobody holds and the command still exits zero.
func TestCheckedWriterRemembersTheFirstFailure(t *testing.T) {
	f := &failingWriter{remaining: 10}
	c := &checkedWriter{w: f}

	c.printf("%s\n", "bootstrap-1 abcdefgh")
	if c.err == nil {
		t.Fatal("a short write was not reported: the token would be lost silently")
	}
	if !errors.Is(c.err, errDiskFull) {
		t.Errorf("err = %v, want the writer's own error", c.err)
	}

	// Later writes are skipped rather than piling up the same fault, and the
	// first failure is the one kept. The writer would report a different error
	// if it were called again, so this distinguishes "kept the first" from
	// "happens to hold an equivalent one".
	f.next = errBrokenPipe
	c.printf("%s\n", "bootstrap-2 ijklmnop")
	if !errors.Is(c.err, errDiskFull) {
		t.Errorf("err = %v, want the first failure to be kept", c.err)
	}
	if strings.Contains(f.written.String(), "bootstrap-2") {
		t.Error("a second token was written after the output had already failed")
	}
}

func TestCheckedWriterReportsNothingWhenTheOutputWorks(t *testing.T) {
	f := &failingWriter{remaining: 1024}
	c := &checkedWriter{w: f}

	c.printf("\n")
	c.printf("%s  %s\n", "bootstrap-1", "npa_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-TOKEN")
	c.printf("\n")

	if c.err != nil {
		t.Fatalf("a working output reported %v", c.err)
	}
	if !strings.Contains(f.written.String(), "bootstrap-1") {
		t.Errorf("the token line did not reach the output: %q", f.written.String())
	}
}
