# 0009. Refuse to load a key encryption key stored inside the data directory

Status: accepted
Date: 2024-05-08

## Context

The specification described envelope encryption at rest, and its own quickstart
then mounted a single volume and placed the KEK file in it, next to the SQLite
database that the KEK protects.

That arrangement provides no confidentiality against the attack it exists to
address. Encryption at rest defends against someone obtaining the stored bytes:
a stolen disk, a copied volume, a backup archive, a snapshot left readable in
object storage. If the key travels in the same volume as the ciphertext, every
one of those events hands over both halves, and the whole mechanism reduces to
obfuscation. The quickstart is also the configuration most deployments keep, so
a defective example becomes the default posture of the installed base.

A related failure is file mode. A keyring readable by group or other is readable
by every process on the box, which is the condition OWASP ASVS 4.0 section 6
asks deployments to avoid for key material.

## Decision

Make the file provider refuse to start rather than warn.

Resolve the configured key path to an absolute path, and compare it against each
configured data directory. If the key resolves inside one of them, fail to load
with an error that says why and names both paths. Separately, reject a keyring
file whose permission bits allow any access by group or other, and require mode
0600.

Provide an environment variable provider for orchestrators that inject secrets
without mounting a file. It parses the keyring, then unsets the variable so the
value is not left in the process environment block for child processes or for
anything reading `/proc`.

Never generate a KEK implicitly at startup. Creation stays an explicit operator
step, because a key that appears by itself is a key nobody has backed up.

## Consequences

The quickstart needs two mounts instead of one, and the failure arrives at
startup for anyone following the old instructions. That is a deliberate
migration cost: the alternative is a deployment that believes it has encryption
at rest and does not.

The path check compares resolved absolute paths and does not follow symbolic
links, so a symlink or a bind mount pointing into the data directory passes it.
It is a guard against the obvious mistake, not a security boundary, and it
cannot be made into one from inside the process.

The environment provider is the weaker of the two. The value exists in the
orchestrator's own state and briefly in the environment block, and Go strings
are immutable so the original copy cannot be overwritten. Unsetting the variable
limits exposure without removing it.
