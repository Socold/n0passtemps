-- 0005_admin_credentials: the passkeys that sign an administrator into the
-- console, and the ceremony state those two round trips need.
--
-- Postgres counterpart of the SQLite migration of the same number. Same tables,
-- same columns in the same order, same constraints; only the types differ where
-- Postgres offers a better one, as in 0001. The reasoning for the design lives
-- in the SQLite file and is summarised here rather than repeated in full.
--
-- The console used to authenticate by a bearer token pasted into a form field.
-- An administrative credential must never authenticate a subject, and a
-- subject's credential must never sign anybody into the console; the second
-- direction is the dangerous one, because it would turn every enrolled user of
-- the deployment into an administrator. Two tables make that a property of
-- where a row lives rather than of a predicate somebody has to remember to
-- write.
--
-- The role comes from the admin_tokens row this credential points at, never
-- from the credential, which is why there is no role column here.

CREATE TABLE admin_credentials (
    id                  TEXT        NOT NULL PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,

    -- Which administrative token this passkey signs in as. It is the identity
    -- the credential proves, and the row that carries the role. ON DELETE
    -- CASCADE because a credential for a token that no longer exists could
    -- authenticate nobody.
    admin_token_id      TEXT        NOT NULL,

    credential_id       BYTEA       NOT NULL,
    public_key          BYTEA       NOT NULL,
    aaguid              BYTEA,
    attestation_type    TEXT        NOT NULL DEFAULT 'none',
    transports          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    sign_count          BIGINT      NOT NULL DEFAULT 0,
    clone_warning       BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_eligible     BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_state        BOOLEAN     NOT NULL DEFAULT FALSE,
    user_verified       BOOLEAN     NOT NULL DEFAULT FALSE,
    binding_hash        BYTEA,
    label               TEXT,
    rp_id               TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT,
    CONSTRAINT adc_token_fk FOREIGN KEY (admin_token_id) REFERENCES admin_tokens (id) ON DELETE CASCADE,
    CONSTRAINT adc_attestation_ck CHECK (attestation_type IN ('none', 'self', 'basic', 'attca', 'anonca', 'indirect')),
    -- The SQLite adc_flags_ck constraint has no counterpart: it existed only to
    -- keep the four INTEGER flag columns within (0, 1), and BOOLEAN admits
    -- nothing else.
    CONSTRAINT adc_sign_count_ck CHECK (sign_count >= 0)
);

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
-- and either could then be completed through the other's endpoint.
--
-- admin_token_id names the token an enrolment ceremony was started for, and is
-- NULL for a sign-in ceremony, which has no identity yet by definition.
CREATE TABLE admin_webauthn_challenges (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    admin_token_id  TEXT,
    ceremony        TEXT        NOT NULL,
    challenge       BYTEA       NOT NULL,
    rp_id           TEXT        NOT NULL,
    session_data    BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    CONSTRAINT adch_ceremony_ck CHECK (ceremony IN ('registration', 'assertion'))
);

CREATE UNIQUE INDEX adch_challenge_uq ON admin_webauthn_challenges (tenant_id, challenge);

-- The janitor's challenge sweep covers this table in the same call that covers
-- webauthn_challenges, so an expired console ceremony is collected without a
-- seventh periodic sweep being added for it.
CREATE INDEX adch_expiry_idx ON admin_webauthn_challenges (expires_at);
