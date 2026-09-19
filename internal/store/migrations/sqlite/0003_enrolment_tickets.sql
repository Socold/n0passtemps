-- 0003_enrolment_tickets: single-use tickets that permit one enrolment.
--
-- A ticket is the way back in for a subject who holds no authenticator yet, or
-- who has lost every one they had. Redeeming it permits exactly one thing:
-- starting and completing one WebAuthn registration. It never produces a signed
-- assertion, so a stolen ticket lets an attacker enrol a key of their own, which
-- is audited and alertable, rather than hand them a session.
--
-- The secret is stored the same way a recovery code is: a clear selector that
-- finds the row in one indexed probe, and an Argon2id hash of the verifier. See
-- internal/crypto/recovery for why hashing rather than sealing under the key
-- encryption key is the right choice for a secret the server never has to read
-- back.
--
-- Delivery is the integrating application's responsibility. This service does
-- not send email and has no outbound network access; it hands the ticket to the
-- caller once, in the issuing response, and never again.

CREATE TABLE enrolment_tickets (
    id                      TEXT    NOT NULL PRIMARY KEY,
    tenant_id               TEXT    NOT NULL,
    subject_id              TEXT    NOT NULL,
    selector                TEXT    NOT NULL,
    verifier_hash           TEXT    NOT NULL,

    -- The identifier of the API key or administrative token that issued it.
    -- A ticket is an account-takeover primitive in the hands of whoever
    -- controls delivery, so the record of who put one into circulation is not
    -- optional; the column is NOT NULL and both issuing routes are
    -- authenticated.
    issued_by               TEXT    NOT NULL,

    -- Free text an operator supplies, for the audit trail. Optional, because
    -- the application onboarding a new user has nothing useful to say here.
    reason                  TEXT,

    created_at              TEXT    NOT NULL,
    expires_at              TEXT    NOT NULL,
    consumed_at             TEXT,

    -- Which credential the redemption produced. Recording it is what lets an
    -- operator answer "what was this ticket used for" rather than only "was it
    -- used". There is deliberately no foreign key: a credential that is later
    -- revoked keeps its row, but one removed by a purge would either block the
    -- deletion or, with ON DELETE SET NULL, silently contradict the pairing
    -- check below. The column is a record of history, not a live reference.
    consumed_credential_id  TEXT,

    revoked_at              TEXT,

    CONSTRAINT et_subject_fk FOREIGN KEY (subject_id) REFERENCES subjects (id) ON DELETE CASCADE,

    -- Consumption and the credential it produced are set together, in one
    -- statement. A row marked consumed with no credential would be a redemption
    -- nobody can account for.
    CONSTRAINT et_consumed_ck CHECK ((consumed_at IS NULL) = (consumed_credential_id IS NULL))
) STRICT;

-- Verification is a lookup on the selector, exactly as for recovery codes. The
-- uniqueness is per tenant, matching rc_selector_uq, so one tenant's selector
-- can never resolve a row belonging to another.
CREATE UNIQUE INDEX et_selector_uq ON enrolment_tickets (tenant_id, selector);

-- At most one live ticket per subject. Issuing a second must replace the first,
-- never add to it: two live tickets double the window in which a stolen one can
-- be redeemed, and an operator who reissues after a failed delivery would
-- otherwise leave the first one working.
--
-- The predicate names only consumption and revocation, not expiry, because
-- expiry is a comparison against the current time and not a column value.
-- ReplaceEnrolmentTicket revokes whatever is live before inserting, so the
-- index never refuses a legitimate issuance; it is the backstop that makes
-- accumulation impossible rather than merely unlikely.
CREATE UNIQUE INDEX et_live_uq ON enrolment_tickets (tenant_id, subject_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

-- The janitor sweep, which deletes past-expiry rows across every tenant.
-- Consumed and revoked tickets go the same way once they are past their
-- expiry: the durable record of a redemption is the audit log, not this table.
CREATE INDEX et_expiry_idx ON enrolment_tickets (expires_at);
