# ADR-004: Persistent Secrets Must Be Encrypted at Rest

## Status

Accepted

## Context

The application handles multiple types of sensitive secret material, including:

- VirusTotal API keys
- Cisco Umbrella Client ID / Client Secret
- Vault entry passwords
- Vault encrypted notes
- Vault custom fields
- KeePass synchronization passwords

These secrets are persisted in application databases and must not be stored as plaintext.

The current implementation uses more than one encryption-key source.

Examples include:

```text
SECRET_KEY_DB
```

used by some application-level encrypted credentials, including:

```text
VirusTotal per-user API keys
Cisco Umbrella credentials
```

and:

```text
VAULT_KEY
```

used by the Vault subsystem for:

```text
Vault passwords
Vault notes
Vault custom fields
Vault KeePass synchronization password
```

These mechanisms already exist and are not assumed to be interchangeable.

## Decision

Persistent secret values must be encrypted at rest before being stored in the application database.

Agents must preserve the existing encryption boundary of each subsystem unless an explicit migration is designed.

The project does **not** require every encrypted value to use one global encryption key.

The security requirement is:

```text
persistent secret
        ↓
appropriate subsystem encryption mechanism
        ↓
ciphertext at rest
```

not:

```text
all secrets must use the same key
```

## Plaintext Lifetime

Plaintext secret values may exist temporarily in application memory when required for legitimate operations such as:

- authenticating to an external API
- revealing an authorized Vault password
- exporting Vault content to KeePass
- importing KeePass content
- rendering a secret only when explicitly required by an authorized workflow

Plaintext lifetime should be minimized.

Plaintext must not be persisted unnecessarily.

## Forbidden Persistence

The following must not be stored as plaintext in normal persistent application storage:

```text
passwords
API keys
client secrets
KeePass master passwords
protected custom fields
sensitive notes
OAuth/access tokens
```

unless an explicit architectural decision documents why encryption is impossible or inappropriate.

## Logging

Secrets must never be written to:

```text
application logs
audit logs
debug output
trace messages
documentation
test fixtures containing real values
AI prompts or responses containing real production values
```

Diagnostic messages must refer to secret presence or failure state without including the secret itself.

Examples:

```text
GOOD:
VirusTotal API key is not configured.

BAD:
VirusTotal API key abc123... failed.
```

## Source Code

Encryption keys themselves must not be hardcoded into application source code.

Keys should come from application/runtime configuration.

Agents must not:

```text
invent replacement keys
commit keys
regenerate existing keys
replace encrypted values with test values in production data
```

## Key Rotation

Changing an encryption key is not a normal configuration-only change when encrypted data already exists.

For example:

```text
VAULT_KEY old
        ↓
existing ciphertext
```

cannot simply be replaced with:

```text
VAULT_KEY new
```

without making existing data unreadable.

Any key rotation must include an explicit migration strategy:

```text
load ciphertext using old key
        ↓
decrypt
        ↓
encrypt using new key
        ↓
persist replacement ciphertext
        ↓
validate
        ↓
retire old key
```

The exact process depends on the affected subsystem.

## Key Separation

Current separation between:

```text
SECRET_KEY_DB
```

and:

```text
VAULT_KEY
```

is accepted.

Agents must not merge them merely to reduce configuration complexity.

A future decision to unify or further separate encryption domains requires:

- threat-model review
- migration strategy
- rollback strategy
- affected-data inventory

and should be documented in a new ADR.

## External API Credentials

External provider credentials must normally be stored encrypted when persisted.

Examples:

```text
VirusTotal API key
Umbrella Client ID / Client Secret
```

Credentials should be decrypted only when needed for the provider operation.

OAuth/access tokens generated from those credentials should normally remain ephemeral unless persistence is explicitly required.

## Vault

Vault is considered a higher-sensitivity subsystem.

Current Vault data encrypted using `VAULT_KEY` includes:

```text
passwords
notes
custom fields
KeePass sync password
```

Agents must not:

- replace encrypted Vault fields with plaintext columns;
- bypass `app/vault/crypto.py`;
- log decrypted Vault values;
- expose secrets in URLs;
- expose secrets in audit details.

## Temporary Files

Encryption-at-rest requirements also apply conceptually to temporary persistent storage.

Temporary files containing plaintext secrets should be avoided.

The current KeePass import-preview workflow writes plaintext secret material to temporary JSON under:

```text
instance/
```

This is documented as technical debt.

Its current existence does not override this ADR.

Future implementations should prefer encrypted or non-persistent temporary state.

## Browser Exposure

A value being encrypted in the database does not make it safe to expose unnecessarily to the browser.

Server-side code should not decrypt a stored secret merely to repopulate an HTML form.

Preferred update pattern:

```text
empty field
    → preserve existing secret

new value supplied
    → replace encrypted secret
```

This applies especially to password/credential settings.

## Database Migrations

Schema or format changes involving encrypted data require special care.

Agents must determine:

```text
what encryption mechanism is used
whether existing ciphertext remains readable
whether re-encryption is required
whether rollback is possible
```

before modifying encrypted columns.

## Tests

Security-sensitive secret handling should eventually be covered by tests verifying:

```text
plaintext is not stored
authorized decrypt succeeds
invalid key/ciphertext fails safely
unauthorized users cannot retrieve secrets
logs/audit do not contain plaintext
```

Tests must use synthetic credentials only.

## Consequences

### Benefits

- Limits exposure from database compromise
- Keeps secret-management behavior consistent
- Reduces accidental plaintext persistence
- Prevents agents from simplifying security boundaries incorrectly

### Costs

- Key management remains operationally important
- Key rotation requires migration work
- Testing encrypted data flows is more complex
- Multiple encryption domains must be understood correctly

## Agent Guidance

Before modifying any field that may contain secret material, determine:

1. Is the value sensitive?
2. Is it persisted?
3. Which encryption mechanism currently protects it?
4. Where is decryption legitimately required?
5. Could the change expose plaintext through logs, UI, files, exports, or audit?
6. Would existing encrypted data remain readable?

If any of these questions are unclear, inspect the relevant subsystem before changing the implementation.

Do not solve uncertainty by reading real secret values.