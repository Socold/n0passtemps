-- 0008_erasure_residue: the indexes a purge needs, and the one guard that two
-- concurrent enrolments were missing.
--
-- Four objects that look unrelated and are not. Three of them exist because
-- PurgeSubject and the janitor now remove personal data this schema used to
-- keep for ever, and a delete that has no index behind it scans the whole
-- table on every pass. The fourth closes a race that the enrolment tickets
-- already had a partial unique index against and the TOTP secrets did not.
--
-- No column changes. erasure_requests.reason is already nullable, which is what
-- allows the purge to clear the operator's free text while leaving the row that
-- proves the erasure happened. The proof is the row: its identifier, its
-- requester, the two instants and the status. The reason is the only field in
-- the table that can hold anything about the person, so it is the only one that
-- goes.

-- alerts carries an optional subject_id, and until now nothing ever removed an
-- alert raised about a subject who has since been erased. PurgeSubject deletes
-- them, which is a delete by (tenant_id, subject_id) on a table indexed only by
-- fingerprint and by severity. The index is partial because the column is NULL
-- on every alert that is about the deployment rather than about a person, and
-- those rows are the majority: a partial index leaves them out of it entirely.
--
-- The same index serves the subject_id filter of ListAlerts, which an operator
-- uses when asking what has been raised about one account.
CREATE INDEX alerts_subject_idx ON alerts (tenant_id, subject_id) WHERE subject_id IS NOT NULL;

-- erasure_requests is read by subject in two places: GetErasureBySubject, on
-- every administrative view of a subject, and the purge that clears the reason
-- from every request ever filed against the subject being erased. The existing
-- er_subject_uq covers neither, because it is restricted to pending requests
-- and a purged or cancelled one falls outside it.
CREATE INDEX er_subject_idx ON erasure_requests (tenant_id, subject_id);

-- Consumed recovery codes used to stay in the table for the life of the
-- account. They are kept for a while on purpose, because a code that was spent
-- is evidence of an authentication, but keeping them for ever has a cost that
-- is not storage: the selector is 30 bits and unique per tenant, so every
-- consumed code that is still there is one more chance for the next batch to
-- collide with it and be refused. The janitor now removes them past a
-- retention window, and this index is what makes that sweep a range scan
-- rather than a full table scan every interval.
--
-- Partial, because an unconsumed code is never a candidate and there are
-- normally far more of those.
CREATE INDEX rc_consumed_idx ON recovery_codes (consumed_at) WHERE consumed_at IS NOT NULL;

-- One pending TOTP secret per subject, enforced by the schema rather than by
-- the statement that creates one.
--
-- CreateTOTPSecret revokes the previous unconfirmed secret and inserts the new
-- one in a transaction. On SQLite that is enough, because one writer runs at a
-- time. Here it is not: under READ COMMITTED two concurrent enrolments for one
-- subject do not see each other's rows, the revocation of each matches nothing
-- the other has written, and both secrets end up live, only one of which the
-- user holds. The enrolment tickets have had a partial unique index against
-- exactly that since 0003; this is its counterpart, and the second inserter now
-- loses on the index instead, which the store reports as a conflict.
--
-- Existing rows first. A database written before this migration may already
-- hold two pending secrets for one subject, and the index would then refuse to
-- be created. The most recent pending secret is the one the user was last
-- shown, so it is the one kept; the rest are revoked, which is what
-- CreateTOTPSecret would have done to them.
UPDATE totp_secrets
SET revoked_at = now()
WHERE revoked_at IS NULL
  AND confirmed_at IS NULL
  AND id <> (
      SELECT newest.id FROM totp_secrets AS newest
      WHERE newest.tenant_id = totp_secrets.tenant_id
        AND newest.subject_id = totp_secrets.subject_id
        AND newest.revoked_at IS NULL
        AND newest.confirmed_at IS NULL
      ORDER BY newest.created_at DESC, newest.id DESC
      LIMIT 1
  );

CREATE UNIQUE INDEX ts_pending_uq ON totp_secrets (tenant_id, subject_id)
    WHERE revoked_at IS NULL AND confirmed_at IS NULL;
