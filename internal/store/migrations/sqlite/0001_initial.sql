-- 0001_initial: core schema for subjects, credentials, secrets and audit.
--
-- Tables are STRICT so that a column declared INTEGER cannot silently accept a
-- string, which SQLite otherwise permits. This raises the minimum engine
-- version to 3.37.
--
-- Every table carries tenant_id even though v1 runs single-tenant. Adding the
-- column later would mean rewriting every query and every index; carrying it
-- from the start costs one integer per row and keeps the phase 6 multi-tenant
-- path open without a migration of the hot tables.

CREATE TABLE tenants (
    id          TEXT    NOT NULL PRIMARY KEY,
    name        TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    CONSTRAINT tenants_status_ck CHECK (status IN ('active', 'suspended'))
) STRICT;

-- The identifier the calling application uses for its own user is treated as
-- personal data: it is very often an email address whatever the documentation
-- recommends. It is therefore never stored in clear.
--
--   ref_hmac   deterministic HMAC-SHA256 under a server-held pepper, so an
--              exact-match lookup stays a single indexed probe
--   ref_sealed envelope-encrypted original, needed only to display something
--              meaningful in the admin interface and to honour a GDPR access
--              request
--
-- An attacker holding the database alone can neither read nor enumerate the
-- identifiers; one holding the database and the pepper can confirm a guess but
-- still not enumerate.
CREATE TABLE subjects (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    ref_hmac        BLOB    NOT NULL,
    ref_sealed      BLOB,
    display_name    TEXT,
    status          TEXT    NOT NULL DEFAULT 'active',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    deleted_at      TEXT,
    CONSTRAINT subjects_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    CONSTRAINT subjects_status_ck CHECK (status IN ('active', 'locked', 'pending_deletion'))
) STRICT;

CREATE UNIQUE INDEX subjects_ref_uq ON subjects (tenant_id, ref_hmac);
CREATE INDEX subjects_status_idx ON subjects (tenant_id, status);
CREATE INDEX subjects_deleted_idx ON subjects (deleted_at) WHERE deleted_at IS NOT NULL;

-- WebAuthn public keys are stored in clear on purpose. They are public keys:
-- the property required of them is integrity, not confidentiality, and sealing
-- them under the KEK would make a KEK loss destroy credentials that are not
-- secret in the first place.
CREATE TABLE webauthn_credentials (
    id                  TEXT    NOT NULL PRIMARY KEY,
    tenant_id           TEXT    NOT NULL,
    subject_id          TEXT    NOT NULL,
    credential_id       BLOB    NOT NULL,
    public_key          BLOB    NOT NULL,
    aaguid              BLOB,
    attestation_type    TEXT    NOT NULL DEFAULT 'none',
    transports          TEXT    NOT NULL DEFAULT '[]',
    sign_count          INTEGER NOT NULL DEFAULT 0,
    clone_warning       INTEGER NOT NULL DEFAULT 0,
    backup_eligible     INTEGER NOT NULL DEFAULT 0,
    backup_state        INTEGER NOT NULL DEFAULT 0,
    user_verified       INTEGER NOT NULL DEFAULT 0,
    binding_hash        BLOB,
    label               TEXT,
    rp_id               TEXT    NOT NULL,
    created_at          TEXT    NOT NULL,
    last_used_at        TEXT,
    revoked_at          TEXT,
    revoked_reason      TEXT,
    CONSTRAINT wc_subject_fk FOREIGN KEY (subject_id) REFERENCES subjects (id) ON DELETE CASCADE,
    CONSTRAINT wc_attestation_ck CHECK (attestation_type IN ('none', 'self', 'basic', 'attca', 'anonca', 'indirect')),
    CONSTRAINT wc_flags_ck CHECK (
        clone_warning IN (0, 1) AND backup_eligible IN (0, 1)
        AND backup_state IN (0, 1) AND user_verified IN (0, 1)
    ),
    CONSTRAINT wc_sign_count_ck CHECK (sign_count >= 0)
) STRICT;

-- The credential ID is unique per relying party, not per subject: the same
-- authenticator must not be registerable twice under different subjects.
CREATE UNIQUE INDEX wc_credential_uq ON webauthn_credentials (tenant_id, rp_id, credential_id);
CREATE INDEX wc_subject_idx ON webauthn_credentials (tenant_id, subject_id) WHERE revoked_at IS NULL;
CREATE INDEX wc_aaguid_idx ON webauthn_credentials (aaguid);

-- TOTP shared secrets are symmetric and must be readable by the server to
-- verify a code, so these are the records that genuinely require envelope
-- encryption.
--
-- last_timestep is the anti-replay state. A code is accepted only if its
-- timestep is strictly greater than the stored value, and the update is applied
-- as a compare-and-swap so two concurrent requests cannot both consume the same
-- timestep.
CREATE TABLE totp_secrets (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    subject_id      TEXT    NOT NULL,
    secret_sealed   BLOB    NOT NULL,
    algorithm       TEXT    NOT NULL DEFAULT 'SHA1',
    digits          INTEGER NOT NULL DEFAULT 6,
    period_seconds  INTEGER NOT NULL DEFAULT 30,
    last_timestep   INTEGER NOT NULL DEFAULT 0,
    label           TEXT,
    created_at      TEXT    NOT NULL,
    confirmed_at    TEXT,
    revoked_at      TEXT,
    CONSTRAINT ts_subject_fk FOREIGN KEY (subject_id) REFERENCES subjects (id) ON DELETE CASCADE,
    CONSTRAINT ts_algorithm_ck CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    CONSTRAINT ts_digits_ck CHECK (digits IN (6, 8)),
    CONSTRAINT ts_period_ck CHECK (period_seconds BETWEEN 15 AND 120),
    CONSTRAINT ts_timestep_ck CHECK (last_timestep >= 0)
) STRICT;

CREATE INDEX ts_subject_idx ON totp_secrets (tenant_id, subject_id) WHERE revoked_at IS NULL;

-- Recovery codes are split into a clear selector and an Argon2id hash of the
-- verifier. See internal/crypto/recovery for why they are hashed rather than
-- sealed.
CREATE TABLE recovery_codes (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    subject_id      TEXT    NOT NULL,
    batch_id        TEXT    NOT NULL,
    selector        TEXT    NOT NULL,
    verifier_hash   TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    consumed_at     TEXT,
    CONSTRAINT rc_subject_fk FOREIGN KEY (subject_id) REFERENCES subjects (id) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX rc_selector_uq ON recovery_codes (tenant_id, selector);
CREATE INDEX rc_subject_idx ON recovery_codes (tenant_id, subject_id) WHERE consumed_at IS NULL;
CREATE INDEX rc_batch_idx ON recovery_codes (batch_id);

-- A WebAuthn ceremony is two round trips, and the challenge issued by the first
-- must be bound to the second. Holding that state server-side rather than in a
-- cookie keeps the service usable by non-browser callers and makes single-use
-- enforcement a database constraint rather than a convention.
CREATE TABLE webauthn_challenges (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    subject_id      TEXT,
    ceremony        TEXT    NOT NULL,
    challenge       BLOB    NOT NULL,
    rp_id           TEXT    NOT NULL,
    session_data    BLOB    NOT NULL,
    created_at      TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    consumed_at     TEXT,
    CONSTRAINT wch_ceremony_ck CHECK (ceremony IN ('registration', 'assertion'))
) STRICT;

CREATE UNIQUE INDEX wch_challenge_uq ON webauthn_challenges (tenant_id, challenge);
CREATE INDEX wch_expiry_idx ON webauthn_challenges (expires_at);

-- Append-only audit log with a hash chain.
--
-- Immutability triggers alone are theatre in an on-premise deployment: the
-- operator owns the database file and can bypass any trigger with the sqlite3
-- shell. The chain does not prevent tampering, it makes tampering detectable,
-- which is the strongest property achievable without an external witness. Each
-- entry commits to the entry before it, so removing or altering one breaks
-- verification for every entry after it.
CREATE TABLE audit_log (
    seq             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT    NOT NULL,
    occurred_at     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    actor_type      TEXT    NOT NULL,
    actor_id        TEXT,
    subject_id      TEXT,
    resource_type   TEXT,
    resource_id     TEXT,
    outcome         TEXT    NOT NULL,
    source_ip       TEXT,
    request_id      TEXT,
    detail          TEXT    NOT NULL DEFAULT '{}',

    -- The personal fields above are committed through pii_digest rather than
    -- hashed directly. Erasing an entry clears subject_id, source_ip and
    -- detail and destroys pii_salt while keeping pii_digest, so the chain
    -- still verifies and the cleared values cannot be recovered from the
    -- digest even when they had little entropy. See package audit.
    pii_salt        BLOB,
    pii_digest      BLOB    NOT NULL,

    prev_hash       BLOB    NOT NULL,
    entry_hash      BLOB    NOT NULL,
    CONSTRAINT al_actor_ck CHECK (actor_type IN ('system', 'api_key', 'admin', 'subject')),
    CONSTRAINT al_outcome_ck CHECK (outcome IN ('success', 'failure', 'denied', 'error'))
) STRICT;

CREATE INDEX al_tenant_time_idx ON audit_log (tenant_id, occurred_at);
CREATE INDEX al_event_idx ON audit_log (tenant_id, event_type, occurred_at);
CREATE INDEX al_subject_idx ON audit_log (tenant_id, subject_id, occurred_at);
CREATE UNIQUE INDEX al_entry_hash_uq ON audit_log (entry_hash);

-- An audit log that literally cannot be modified cannot honour an erasure
-- request, and one that cannot be trimmed grows without bound. Both needs are
-- real, so rather than weakening the guard into a convention, each is allowed
-- as one narrow, attested exception and everything else is refused.
--
-- Exception one, erasure. The update must clear the personal fields, destroy
-- the salt, and leave every other column bit for bit identical, including the
-- digest and both hashes. Anything else aborts.
CREATE TRIGGER audit_log_update_guard
BEFORE UPDATE ON audit_log
WHEN NOT (
        NEW.subject_id IS NULL
    AND NEW.source_ip  IS NULL
    AND NEW.pii_salt   IS NULL
    AND NEW.detail     = '{}'
    AND OLD.pii_salt   IS NOT NULL
    AND NEW.seq           =  OLD.seq
    AND NEW.tenant_id     =  OLD.tenant_id
    AND NEW.occurred_at   =  OLD.occurred_at
    AND NEW.event_type    =  OLD.event_type
    AND NEW.actor_type    =  OLD.actor_type
    AND NEW.actor_id      IS OLD.actor_id
    AND NEW.resource_type IS OLD.resource_type
    AND NEW.resource_id   IS OLD.resource_id
    AND NEW.outcome       =  OLD.outcome
    AND NEW.request_id    IS OLD.request_id
    AND NEW.pii_digest    =  OLD.pii_digest
    AND NEW.prev_hash     =  OLD.prev_hash
    AND NEW.entry_hash    =  OLD.entry_hash
)
BEGIN
    SELECT RAISE(ABORT, 'audit_log permits no update other than erasure of the personal fields');
END;

-- Exception two, retention. An entry may be removed only once a checkpoint has
-- recorded that the log was trimmed through its sequence number. Moving that
-- watermark is itself an audited event which commits to the hash of the last
-- entry removed, so verification resumes from the checkpoint and the trim
-- cannot be carried out silently.
CREATE TRIGGER audit_log_delete_guard
BEFORE DELETE ON audit_log
WHEN OLD.seq > COALESCE((SELECT MAX(pruned_through_seq) FROM audit_checkpoints), 0)
BEGIN
    SELECT RAISE(ABORT, 'audit_log entries may only be removed below a recorded retention checkpoint');
END;

-- The watermark, and the chain hash verification has to resume from.
--
-- pruned_through_seq only ever moves forward: a checkpoint that lowered it
-- would re-expose already deleted rows to the delete guard, so the CHECK plus
-- the append-only trigger below keep the sequence monotonic.
CREATE TABLE audit_checkpoints (
    id                  TEXT    NOT NULL PRIMARY KEY,
    tenant_id           TEXT    NOT NULL,
    pruned_through_seq  INTEGER NOT NULL,
    pruned_through_hash BLOB    NOT NULL,
    entries_removed     INTEGER NOT NULL,
    audit_seq           INTEGER NOT NULL,
    created_at          TEXT    NOT NULL,
    CONSTRAINT ac_seq_ck CHECK (pruned_through_seq > 0 AND entries_removed >= 0)
) STRICT;

CREATE UNIQUE INDEX ac_seq_uq ON audit_checkpoints (pruned_through_seq);

CREATE TRIGGER audit_checkpoints_no_change
BEFORE UPDATE ON audit_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'audit_checkpoints is append-only');
END;

CREATE TRIGGER audit_checkpoints_no_delete
BEFORE DELETE ON audit_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'audit_checkpoints is append-only');
END;

-- Credentials that authenticate callers of the service.
--
-- api_keys authenticate the application integrating n0passtemps and are
-- required on every /v1 endpoint. Without them, an unauthenticated
-- /v1/webauthn/{subject}/register would let anyone enrol an authenticator
-- against any subject, which is a complete authentication bypass.
CREATE TABLE api_keys (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    selector        TEXT    NOT NULL,
    verifier_hash   TEXT    NOT NULL,
    scopes          TEXT    NOT NULL DEFAULT '[]',
    created_at      TEXT    NOT NULL,
    created_by      TEXT,
    last_used_at    TEXT,
    expires_at      TEXT,
    revoked_at      TEXT,
    CONSTRAINT ak_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) STRICT;

CREATE UNIQUE INDEX ak_selector_uq ON api_keys (selector);
CREATE INDEX ak_tenant_idx ON api_keys (tenant_id) WHERE revoked_at IS NULL;

CREATE TABLE admin_tokens (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    selector        TEXT    NOT NULL,
    verifier_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    created_by      TEXT,
    last_used_at    TEXT,
    expires_at      TEXT,
    revoked_at      TEXT,
    CONSTRAINT at_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    CONSTRAINT at_role_ck CHECK (role IN ('admin_full', 'admin_operator', 'admin_auditor'))
) STRICT;

CREATE UNIQUE INDEX at_selector_uq ON admin_tokens (selector);
CREATE INDEX at_tenant_idx ON admin_tokens (tenant_id) WHERE revoked_at IS NULL;

-- Fixed-window counters for throttling. Keyed by a caller-chosen bucket string
-- so the same table serves per-subject, per-IP and per-key limits.
-- The primary key is (tenant_id, bucket_key), not bucket_key alone. With a
-- global key a tenant predicate can only refuse a foreign bucket, never isolate
-- one, so two tenants deriving the same key would share a counter.
--
-- subject_id records which subject a per-subject bucket belongs to. The key
-- itself is an opaque hash, so without this column no predicate could find a
-- subject's buckets, and purging a subject would leave their throttle state
-- behind. That is a retention obligation under GDPR Article 17, not a
-- housekeeping nicety. It is NULL for the buckets keyed on an address or an API
-- key, which belong to no single subject.
CREATE TABLE throttle_buckets (
    bucket_key      TEXT    NOT NULL,
    tenant_id       TEXT    NOT NULL,
    subject_id      TEXT,
    window_start    TEXT    NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    failures        INTEGER NOT NULL DEFAULT 0,
    blocked_until   TEXT,
    updated_at      TEXT    NOT NULL,
    CONSTRAINT tb_pk PRIMARY KEY (tenant_id, bucket_key),
    CONSTRAINT tb_attempts_ck CHECK (attempts >= 0 AND failures >= 0)
) STRICT;

CREATE INDEX tb_blocked_idx ON throttle_buckets (blocked_until) WHERE blocked_until IS NOT NULL;
CREATE INDEX tb_subject_idx ON throttle_buckets (tenant_id, subject_id) WHERE subject_id IS NOT NULL;
