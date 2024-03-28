package zeroize

import (
	"bytes"
	"fmt"
	"testing"
)

func TestBytesZeroesEveryByte(t *testing.T) {
	// 0 and 1 are the boundary lengths; 32 is the size of the keys this
	// package exists for; 4096 crosses the sizes at which a runtime may switch
	// to a bulk clearing routine.
	for _, n := range []int{0, 1, 32, 4096} {
		t.Run(fmt.Sprintf("length %d", n), func(t *testing.T) {
			// No byte starts at zero, so a byte left untouched is visible.
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(i%255) + 1
			}
			Bytes(b)
			for i, v := range b {
				if v != 0 {
					t.Fatalf("byte %d of %d still holds %#x: secret material survives zeroization", i, n, v)
				}
			}
		})
	}
}

// Bytes runs in deferred calls on error paths, where the slice may never have
// been allocated. A panic there would replace the original error and could
// take the server down.
func TestBytesToleratesNilAndEmpty(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"nil slice", nil},
		{"empty slice", []byte{}},
		{"zero length slice with capacity", make([]byte, 0, 8)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Bytes panicked on a %s: %v", tc.name, r)
				}
			}()
			Bytes(tc.in)
		})
	}
}

// Callers zeroize one field of a larger buffer, for example the verifier part
// of a parsed credential. Writing outside the window would corrupt the
// neighbouring data, and the bytes after the window are reachable through the
// capacity of the sub-slice, so both sides are checked.
func TestBytesOnlyTouchesTheGivenWindow(t *testing.T) {
	cases := []struct {
		name     string
		from, to int
	}{
		{"window in the middle", 16, 32},
		{"window at the start", 0, 8},
		{"window at the end", 56, 64},
		{"single byte window", 31, 32},
		{"empty window", 20, 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.Repeat([]byte{0xAA}, 64)
			Bytes(buf[tc.from:tc.to])
			for i, v := range buf {
				inside := i >= tc.from && i < tc.to
				switch {
				case inside && v != 0:
					t.Fatalf("byte %d inside the window was not zeroed", i)
				case !inside && v != 0xAA:
					t.Fatalf("byte %d outside the window [%d,%d) was overwritten with %#x", i, tc.from, tc.to, v)
				}
			}
		})
	}
}
