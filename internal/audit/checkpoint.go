package audit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// PruneAction is what the action field of a retention marker says.
//
// The marker is an ordinary chain entry, so it is covered by the hashes like
// any other, and it is the only thing in the log that records a trim. The
// constant is here rather than spelled out in each store so that the two
// engines cannot drift apart on the one string a verifier matches on.
const PruneAction = "retention_prune"

// PruneMarkerDetail renders the detail document of the entry a retention trim
// appends before it removes anything.
//
// The boundary hash is in the document, and that is the point of this
// function. The detail takes part in the chain through the salted digest of
// the personal fields, so writing the hash here commits the chain to the exact
// entry the trim stopped at. A checkpoint row claiming some other boundary no
// longer has anything in the log agreeing with it, and verification says so.
//
// The hash is hex rather than the base64 the admin API renders hashes in,
// because the insert guard on audit_checkpoints is written in SQL and hex is
// the one encoding both SQLite and PostgreSQL produce without an extension.
// The document is read back by MarkerAttestsCheckpoint and by those two
// guards, and by nothing else.
//
// What this does not do is make a trim impossible to forge. Whoever owns the
// database can write a marker of their own, chain it onto the head and delete
// the prefix it names, and the result verifies, because it is what an honest
// trim looks like. It is the same limit the chain has everywhere: see the
// package comment. What it does buy is that the trim cannot happen quietly.
// Removing a prefix now requires an entry in the chain that says so, names the
// boundary and commits to its hash, which every reader of the log and the
// external witness both see.
func PruneMarkerDetail(throughSeq int64, throughHash []byte, entries int64) []byte {
	return []byte(fmt.Sprintf(
		`{"action":%q,"pruned_through_seq":%d,"pruned_through_hash":%q,"entries":%d}`,
		PruneAction, throughSeq, hex.EncodeToString(throughHash), entries))
}

// MarkerAttestsCheckpoint reports whether detail is the marker of a trim
// through exactly this boundary.
//
// It parses rather than compares text, because PostgreSQL stores the document
// as JSONB and hands it back in the server's own spelling: the keys come back
// in another order and a space follows every colon, so the bytes a store reads
// are not the bytes PruneMarkerDetail wrote.
//
// A boundary hash of the wrong length is refused outright. Without that, a
// checkpoint carrying no hash at all would be attested by a marker that
// carries none either, which is the comparison this exists to prevent.
func MarkerAttestsCheckpoint(detail []byte, throughSeq int64, throughHash []byte) bool {
	if len(throughHash) != HashSize {
		return false
	}

	var marker struct {
		Action string `json:"action"`
		Seq    int64  `json:"pruned_through_seq"`
		Hash   string `json:"pruned_through_hash"`
	}
	if err := json.Unmarshal(detail, &marker); err != nil {
		return false
	}

	return marker.Action == PruneAction &&
		marker.Seq == throughSeq &&
		strings.EqualFold(marker.Hash, hex.EncodeToString(throughHash))
}
