-- 0005_admin_credentials: the passkeys that sign an administrator into the
-- console, and the ceremony state those two round trips need.
--
-- The console used to authenticate by a bearer token pasted into a form field.
-- A passwordless product whose own administration interface asks for a pasted
-- secret is an awkward demonstration, and the pasted secret is the long-lived
-- credential itself: it lands in the browser's form history, in a password
-- manager entry nobody audits, and on the screen of whoever is standing behind
-- the operator.
--
-- # Why this is a second table and not a column on webauthn_credentials
--
-- An administrative credential must never authenticate a subject, and a
-- subject's credential must never sign anybody into the console. Both
-- directions matter, and the second is the dangerous one: it would turn every
-- enrolled user of the deployment into an administrator.
--
-- Two tables make that a property of where a row lives rather than of a
-- predicate somebody has to remember to write. The subject assertion paths
-- resolve a credential through webauthn_credentials and read nothing here; the
-- console resolves one through this table and reads nothing there. A forgotten
-- WHERE clause cannot reach across, because there is no clause that would.
--
-- The separation is reinforced twice more, in Go rather than in the schema. The
-- relying-party user handle is derived under a different domain separator for
-- an administrative credential, so an authenticator asked to enrol one creates
-- a credential distinct from any it holds for a subject, and a response whose
-- handle belongs to the other space is refused. And neither registration
-- ceremony will store a credential identifier that already exists in the other
-- table, so "no credential is both" is a stored invariant and not only a
-- consequence of how handles are built.
--
-- # What it does not change
--
-- The role comes from the admin_tokens row this credential points at, never
-- from the credential. A passkey proves who is signing in and carries no
-- authority of its own, which is why there is no role column here.
--
-- The bearer token does not go away. It is how the first administrator exists
-- at all, and it is the way back in when a passkey is lost; see
-- docs/adr/0014 and docs/adr/0017.

CREATE TABLE admin_credentials (
    id                  TEXT    NOT NULL PRIMARY KEY,
    tenant_id           TEXT    NOT NULL,

    -- Which administrative token this passkey signs in as. It is the identity
    -- the credential proves, and the row that carries the role. ON DELETE
    -- CASCADE because a credential for a token that no longer exists could
    -- authenticate nobody: the sign-in path resolves the token from this
    -- column and refuses when it is missing, so a stranded row would be dead
    -- weight that still appears in a listing.
    admin_token_id      TEXT    NOT NULL,

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
    CONSTRAINT adc_token_fk FOREIGN KEY (admin_token_id) REFERENCES admin_tokens (id) ON DELETE CASCADE,
    CONSTRAINT adc_attestation_ck CHECK (attestation_type IN ('none', 'self', 'basic', 'attca', 'anonca', 'indirect')),
    CONSTRAINT adc_flags_ck CHECK (
        clone_warning IN (0, 1) AND backup_eligible IN (0, 1)
        AND backup_state IN (0, 1) AND user_verified IN (0, 1)
    ),
    CONSTRAINT adc_sign_count_ck CHECK (sign_count >= 0)
) STRICT;

-- The credential identifier is unique per relying party, exactly as for a
-- subject credential: the same authenticator must not be enrolled twice under
-- two administrative tokens, because an assertion carries the credential
-- identifier and nothing else that would say which of the two it meant.
CREATE UNIQUE INDEX adc_credential_uq ON admin_credentials (tenant_id, rp_id, credential_id);

-- The enrolment listing and the count behind admin.passkey_required, both of
-- which ask only about credentials that still work.
CREATE INDEX adc_token_idx ON admin_credentials (tenant_id, admin_token_id) WHERE revoked_at IS NULL;

-- Ceremony state for the console, held apart from webauthn_challenges for the
-- reason the credentials are held apart from webauthn_credentials.
--
-- Without the separation, a challenge issued by the console's unauthenticated
-- sign-in route would be indistinguishable from one issued by the subject
-- usernameless route: both name no identity, both require user verification,
-- and either could then be completed through the other's endpoint. That is a
-- caller choosing which route's rate limit and which route's checks apply to a
-- ceremony, which is precisely the substitution the two credential spaces exist
-- to prevent. A row in this table is not visible to ConsumeChallenge, and a row
-- in that one is not visible to ConsumeAdminChallenge.
--
-- admin_token_id names the token an enrolment ceremony was started for, and is
-- NULL for a sign-in ceremony, which has no identity yet by definition. The
-- completion of each requires the other's value to be absent, so neither can be
-- finished through the other's route either.
CREATE TABLE admin_webauthn_challenges (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    admin_token_id  TEXT,
    ceremony        TEXT    NOT NULL,
    challenge       BLOB    NOT NULL,
    rp_id           TEXT    NOT NULL,
    session_data    BLOB    NOT NULL,
    created_at      TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    consumed_at     TEXT,
    CONSTRAINT adch_ceremony_ck CHECK (ceremony IN ('registration', 'assertion'))
) STRICT;

CREATE UNIQUE INDEX adch_challenge_uq ON admin_webauthn_challenges (tenant_id, challenge);

-- The janitor's challenge sweep covers this table in the same call that covers
-- webauthn_challenges, so an expired console ceremony is collected without a
-- seventh periodic sweep being added for it.
CREATE INDEX adch_expiry_idx ON admin_webauthn_challenges (expires_at);
