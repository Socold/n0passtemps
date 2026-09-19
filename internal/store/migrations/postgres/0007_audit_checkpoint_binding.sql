-- 0007_audit_checkpoint_binding: a checkpoint is worth what the chain says it is.
--
-- A checkpoint is where verification resumes once a prefix of the log has been
-- trimmed, so a row here decides how much of the log a verifier never looks at.
-- Until now the table was guarded against UPDATE and DELETE and against nothing
-- on the way in, and the marker the trim appends to the chain named the
-- boundary sequence number but not its hash. Whoever could write to the
-- database could therefore insert a checkpoint naming entry N and the hash of
-- entry N, delete entries 1 to N, which the delete guard then allowed because a
-- checkpoint existed, and leave a log that verified from N onwards with no
-- trace of the entries that had gone.
--
-- Two conditions close that. The first is in the chain rather than here: the
-- marker now commits to the boundary hash, because its detail document takes
-- part in the entry hash. The second is below: a checkpoint is admitted only
-- when the entry it names is really that marker and really says what the
-- checkpoint says. Verification asks the same question on the way out, since
-- whoever owns the cluster can drop a trigger.
--
-- What is not closed, and cannot be by anything inside the database, is the
-- attacker who rewrites the log from end to end: they can write their own
-- marker, chain it onto the head and delete the prefix it names, and the result
-- is exactly what an honest trim looks like. The property gained is that a
-- prefix cannot leave quietly. Removing one now costs an entry in the chain
-- that says so, names the boundary and commits to its hash, and that entry is
-- read by every reader of the log and delivered to the external witness. See
-- internal/audit/checkpoint.go and docs/SIEM.md.
--
-- A deployment that trimmed its log before this migration has a checkpoint
-- whose marker predates the binding, and verification reports it from here on.
-- That is the honest reading rather than a false alarm: a checkpoint written
-- before the boundary hash entered the chain is precisely one that cannot be
-- told apart from an inserted one. It clears at the next retention pass, which
-- writes a checkpoint the chain attests.
--
-- The comparison on the sequence number is between two jsonb numbers rather
-- than between casts of their text, so a document holding something other than
-- a number is a mismatch instead of a cast that raises. The hash is compared as
-- hex, which is the one encoding both engines produce without an extension, and
-- it is what internal/audit writes into the marker for that reason.
CREATE FUNCTION audit_checkpoints_insert_guard() RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_log
        WHERE seq = NEW.audit_seq
          AND detail->>'action' = 'retention_prune'
          AND detail->'pruned_through_seq' = to_jsonb(NEW.pruned_through_seq)
          AND detail->>'pruned_through_hash' = encode(NEW.pruned_through_hash, 'hex')
    ) THEN
        RAISE EXCEPTION 'audit_checkpoints is append-only and takes no row that the marker it names does not attest';
    END IF;

    -- The boundary has to be an entry that is still there, holding the hash the
    -- checkpoint claims for it. The trim inserts the checkpoint before it
    -- deletes anything, so an honest one always satisfies this; a row naming a
    -- boundary nobody can check is the shape a forgery takes.
    IF NOT EXISTS (
        SELECT 1 FROM audit_log
        WHERE seq = NEW.pruned_through_seq AND entry_hash = NEW.pruned_through_hash
    ) THEN
        RAISE EXCEPTION 'audit_checkpoints is append-only and takes no row whose boundary entry is not present';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_checkpoints_insert_guard
BEFORE INSERT ON audit_checkpoints
FOR EACH ROW
EXECUTE FUNCTION audit_checkpoints_insert_guard();
