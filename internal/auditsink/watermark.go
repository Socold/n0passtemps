package auditsink

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// watermark records how far delivery has got, so that a restart resumes instead
// of resending the whole log.
//
// It is a file rather than a row in the database. The audit table takes no
// updates at all, by trigger, and the point of the whole feature is that a
// hosted receiver, not this database, is the durable record; a second table
// here would be one more thing an operator restoring a backup could put back
// out of step with the receiver. A file holds one integer, is written
// atomically, and losing it costs a redelivery rather than a gap.
//
// It is not a secret. Anyone who can read it learns how many audit entries
// exist, which they can also learn from the health report they are already
// authenticated for. It is still written 0600, because nothing this service
// writes into the data directory needs to be world readable.
type watermark struct {
	path string

	mu  sync.RWMutex
	seq int64
}

// watermarkFile is the on-disk form.
//
// JSON with a named field rather than a bare number, so that a person who opens
// the file can tell what it is, and so a later version can add a field without
// the old format becoming ambiguous. UpdatedAt is for that reader too: nothing
// in the code consults it.
type watermarkFile struct {
	DeliveredThroughSeq int64     `json:"delivered_through_seq"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// loadWatermark reads the file, or starts from zero when there is none.
//
// A missing file is the normal first start. A file that cannot be read or cannot
// be parsed is reported at error level and treated as zero, which resends
// everything the log still holds: the receiver de-duplicates on the sequence
// number, so the cost is traffic, whereas guessing a higher value would skip
// entries and nothing would ever go looking for them.
//
// The one thing that is fatal is a directory that cannot be written, which is
// checked here by writing the value straight back. An unwritable watermark means
// every batch would be delivered and then delivered again after the next
// restart, for ever, and that is a misconfiguration to refuse at startup rather
// than to discover from an alert.
func loadWatermark(path string, log *slog.Logger) (*watermark, error) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil, fmt.Errorf("%w: no path was given", ErrWatermark)
	}

	w := &watermark{path: path}

	// #nosec G304 -- the watermark path comes from the operator's own configuration, and reading the file they named is
	// the whole purpose of this function
	raw, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		// First start with a sink configured.
	case err != nil:
		log.Error("the audit sink watermark could not be read, delivery restarts from the beginning of the log",
			slog.String("path", path), slog.Any("error", err))
	default:
		var f watermarkFile
		if err := json.Unmarshal(raw, &f); err != nil {
			log.Error("the audit sink watermark is not readable as JSON, delivery restarts from the beginning of the log",
				slog.String("path", path), slog.Any("error", err))
		} else if f.DeliveredThroughSeq > 0 {
			w.seq = f.DeliveredThroughSeq
		}
	}

	if err := w.set(time.Now().UTC(), w.seq); err != nil {
		return nil, err
	}
	return w, nil
}

// get returns the last sequence number the receiver acknowledged.
func (w *watermark) get() int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.seq
}

// set records seq durably and only then moves the in-memory value.
//
// The write is a temporary file, an fsync and a rename, which is atomic within
// the directory. Writing in place would leave a half-written file after a power
// loss, and a half-written watermark is worse than a missing one: the missing
// one resends, the truncated one could parse as a smaller number, or not parse
// at all.
//
// Sequence numbers only ever move forwards. A caller asking for a lower one is
// ignored rather than obeyed, because the only way that can happen is a stale
// in-flight batch, and honouring it would resend entries the receiver has
// already acknowledged for no benefit.
func (w *watermark) set(now time.Time, seq int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq < w.seq {
		return nil
	}

	body, err := json.Marshal(watermarkFile{DeliveredThroughSeq: seq, UpdatedAt: now})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWatermark, err)
	}

	tmp := w.path + ".tmp"
	// #nosec G304 -- the temporary file sits beside the operator-configured watermark path, which is the only place it
	// can be renamed from atomically
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWatermark, err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%w: %v", ErrWatermark, err)
	}
	// The sync is what makes the ordering mean anything. Without it the
	// rename could land while the contents were still in the page cache, and a
	// power loss would leave a watermark naming a batch that was never written.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%w: %v", ErrWatermark, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%w: %v", ErrWatermark, err)
	}
	if err := os.Rename(tmp, w.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%w: %v", ErrWatermark, err)
	}

	w.seq = seq
	return nil
}
