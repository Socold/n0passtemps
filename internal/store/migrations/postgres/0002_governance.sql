-- 0002_governance: alerting, dual-approval and GDPR erasure tracking.
--
-- These tables exist in every deployment. The features that write to them are
-- gated by configuration, not by schema, so switching a deployment from lite to
-- complete never requires a migration.

CREATE TABLE alerts (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    alert_type      TEXT        NOT NULL,
    severity        TEXT        NOT NULL,
    subject_id      TEXT,
    resource_id     TEXT,
    summary         TEXT        NOT NULL,
    detail          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    fingerprint     TEXT        NOT NULL,
    occurrences     INTEGER     NOT NULL DEFAULT 1,
    first_seen_at   TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    CONSTRAINT alerts_severity_ck CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT alerts_occurrences_ck CHECK (occurrences >= 1)
);

-- Repeated instances of the same condition collapse onto one row by
-- fingerprint. An alert list that grows one row per failed login is an alert
-- list nobody reads.
CREATE UNIQUE INDEX alerts_fingerprint_uq ON alerts (tenant_id, fingerprint) WHERE acknowledged_at IS NULL;
CREATE INDEX alerts_open_idx ON alerts (tenant_id, severity, last_seen_at) WHERE acknowledged_at IS NULL;

-- Dual-approval queue. A sensitive operation is recorded here instead of being
-- executed, and runs only once a second distinct administrator approves it.
--
-- requested_by and decided_by must differ. Postgres could express that as a
-- CHECK, unlike SQLite, but the rule stays in the store for both backends: one
-- invariant held in two places drifts, and a deployment would then reject a
-- decision on Postgres that SQLite accepts.
CREATE TABLE approval_requests (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    operation       TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    reason          TEXT,
    status          TEXT        NOT NULL DEFAULT 'pending',
    requested_by    TEXT        NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    decided_by      TEXT,
    decided_at      TIMESTAMPTZ,
    decision_note   TEXT,
    executed_at     TIMESTAMPTZ,
    execution_error TEXT,
    CONSTRAINT ar_status_ck CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'executed', 'failed'))
);

CREATE INDEX ar_pending_idx ON approval_requests (tenant_id, status, requested_at);
CREATE INDEX ar_expiry_idx ON approval_requests (expires_at) WHERE status = 'pending';

-- GDPR erasure requests.
--
-- Erasure is deliberately two-phase. Article 17 grants a right to erasure, but
-- an immediate hard delete destroys the audit trail that proves the erasure was
-- legitimate, and gives an attacker who obtains one admin token a way to wipe
-- accounts irreversibly. The subject is therefore blocked from authenticating
-- at once, and the row is purged after the retention window.
--
-- The audit entries that refer to the subject survive the purge with the
-- subject reference removed, which keeps the hash chain intact.
CREATE TABLE erasure_requests (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    subject_id      TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending',
    reason          TEXT,
    requested_by    TEXT        NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL,
    purge_after     TIMESTAMPTZ NOT NULL,
    cancelled_by    TEXT,
    cancelled_at    TIMESTAMPTZ,
    purged_at       TIMESTAMPTZ,
    CONSTRAINT er_status_ck CHECK (status IN ('pending', 'cancelled', 'purged'))
);

CREATE UNIQUE INDEX er_subject_uq ON erasure_requests (tenant_id, subject_id) WHERE status = 'pending';
CREATE INDEX er_due_idx ON erasure_requests (purge_after) WHERE status = 'pending';
