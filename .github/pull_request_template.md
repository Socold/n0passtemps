## What this changes

<!-- One paragraph. Link the issue it closes, if there is one. -->

## Checklist

- [ ] Tests cover the change, and a fix comes with a test that failed before it
- [ ] `make ci` passes locally
- [ ] No secret, keyring, token or real credential is in the diff or the history
- [ ] Schema changes ship a migration for both SQLite and PostgreSQL, and `make migrate-check` passes
- [ ] Documentation under `docs/` and the OpenAPI spec reflect the new behaviour

## Notes for the reviewer

<!-- Anything that is not obvious from the diff: a rejected alternative, a
behaviour change an operator has to know about, a follow-up left out on
purpose. -->
