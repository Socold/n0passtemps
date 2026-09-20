-- 0004_janitor_lease: the lease that keeps two replicas from sweeping at once.
--
-- Postgres counterpart of the SQLite migration of the same number. Same table,
-- same columns in the same order; only the timestamp type differs, TIMESTAMPTZ
-- rather than an RFC3339 string.
--
-- The janitor runs in process, so a deployment with several replicas performs
-- every sweep once per replica. The sweeps are idempotent conditional deletes,
-- so that is waste rather than damage, and this table exists to remove the
-- waste and nothing else: no sweep depends on the lease being available, and
-- losing the race is a skipped pass rather than an error.
--
-- The PostgreSQL implementation leaves this table empty, deliberately, and the
-- table is declared here so that both engines declare the same schema, which is
-- asserted by TestSchemaParity and by make migrate-check. It coordinates its
-- replicas with a session-level advisory lock instead, because such a lock is
-- dropped by the server the moment the holder's connection dies: a replica
-- killed with SIGKILL mid-sweep frees it as fast as the kernel closes its
-- sockets, and the next pass anywhere in the deployment finds it free. No
-- expiry can match that, and an expiry is the best a row can offer. See
-- TryAcquireJanitorLock in internal/store/postgres/janitor.go.
--
-- The table is therefore not dead weight for one engine only by accident: it is
-- the SQLite mechanism, declared in both sets because the parity check is worth
-- more than the one empty relation it costs.

CREATE TABLE janitor_leases (
    -- Which periodic task the lease belongs to. Today there is one, the
    -- janitor sweep.
    name        TEXT        NOT NULL PRIMARY KEY,

    -- The replica holding it, as a host and a process identifier. It is a
    -- label for an operator and the condition on the release, so that a
    -- process whose lease ran out mid-sweep cannot delete the row a later
    -- holder wrote. It is not a credential and nothing authorises on it.
    owner       TEXT        NOT NULL,

    acquired_at TIMESTAMPTZ NOT NULL,

    -- When the lease stops meaning anything.
    expires_at  TIMESTAMPTZ NOT NULL
);
