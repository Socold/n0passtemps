-- 0004_janitor_lease: the lease that keeps two replicas from sweeping at once.
--
-- The janitor runs in process, so a deployment with several replicas performs
-- every sweep once per replica. The sweeps are idempotent conditional deletes,
-- so that is waste rather than damage, and this table exists to remove the
-- waste and nothing else: no sweep depends on the lease being available, and
-- losing the race is a skipped pass rather than an error.
--
-- One row, named rather than anonymous, so that a second periodic task needing
-- the same coordination does not need a table of its own.
--
-- The expiry is what makes a replica killed mid-sweep recover without help. A
-- holder that dies never deletes its row, so the row has to stop meaning
-- anything on its own; the janitor takes the lease for exactly as long as one
-- sweep is allowed to run, and the first pass after that takes it over. Nothing
-- has to notice the death and no operator has to clear the row.
--
-- On SQLite this is a real lease and not a no-op, even though the engine admits
-- one writer. The write lock serialises the statement that takes the lease; it
-- does nothing about two processes that have each taken it and moved on to the
-- sweep. One process and one file is the only supported arrangement here, and
-- there the lease is uncontended, but nothing prevents two processes from
-- opening one file over a network mount, and there this row is what stands
-- between them and two concurrent sweeps.

CREATE TABLE janitor_leases (
    -- Which periodic task the lease belongs to. Today there is one, the
    -- janitor sweep.
    name        TEXT NOT NULL PRIMARY KEY,

    -- The replica holding it, as a host and a process identifier. It is a
    -- label for an operator and the condition on the release, so that a
    -- process whose lease ran out mid-sweep cannot delete the row a later
    -- holder wrote. It is not a credential and nothing authorises on it.
    owner       TEXT NOT NULL,

    acquired_at TEXT NOT NULL,

    -- When the lease stops meaning anything. Compared as text, which is exact
    -- because the timestamp layout is fixed width, so string order is time
    -- order.
    expires_at  TEXT NOT NULL
) STRICT;
