# Configuration

The default configuration path is `$XDG_CONFIG_HOME/imapledger/config.toml`, or `~/.config/imapledger/config.toml` when `XDG_CONFIG_HOME` is unset. The separate schema-2 rules file is named `rules.toml` beside the selected config file. The IMAP password is never written to configuration. If `[imap.auth]` is omitted, credential resolution uses hidden prompt authentication, preserving existing behavior. Credential-consuming commands resolve once per invocation; legacy bare `clean` reuses the credential across its configured sources, while positional `clean FOLDER` processes one source.

## IMAP credential sources

`[imap.auth].source` accepts `prompt`, `keyring`, or `vault`. It selects where imapledger
obtains the IMAP password, not where it is written in TOML. `imapledger config show`
displays the selected source, effective vault minimum, and non-secret `vault_path`, but never a password, vault
passphrase, or ciphertext, and does not connect to IMAP.

```toml
[imap.auth]
source = "prompt"
```

Prompt mode is the compatibility default. Stored credentials are opt-in through `auth set`,
which reads the IMAP password using hidden input and never accepts it as a command-line
argument:

```bash
imapledger auth set
imapledger auth set --storage keyring
imapledger auth set --storage vault
imapledger auth set --storage vault --replace
imapledger auth status --verbose
imapledger auth delete
imapledger auth change-passphrase
```

`auth set` defaults to `--storage auto`. Auto probes for an approved native OS keyring and
uses it when available. If keyring support or a supported backend is unavailable, the
command fails before prompting for secrets and shows explicit choices. It never silently
falls back to a file vault or prompt mode:

```text
No supported OS keyring is available.

Install:
    pip install 'imapledger[keyring]'

or use the encrypted file vault explicitly:
    imapledger auth set --storage vault
```

Choose `--storage keyring` to require an OS keyring, or `--storage vault` to explicitly
select the encrypted VaultConfig file. `--storage encrypted-file` remains an alias for
`vault`. Keyring support is optional and accepts only supported native OS keyrings.

For a file vault, `[imap.auth].vault_path` optionally selects its location:

```toml
[imap.auth]
source = "vault"
vault_path = "~/.local/share/imapledger/credentials.enc"
vault_min_passphrase_length = 10
```

When omitted, imapledger uses `$XDG_DATA_HOME/imapledger/credentials.enc`, or
`~/.local/share/imapledger/credentials.enc` when `XDG_DATA_HOME` is unset. A configured
`~` is expanded at use time. The path is not secret, is safe to show in configuration, and
allows separate config files to use separate vaults. The configured path is used by
`auth set`, `auth status`, `auth delete`, `auth change-passphrase`, and runtime credential
resolution.

New stored credentials are not overwritten by default. If the account already exists in
the selected backend, `auth set` fails without changing the config or secret. Use
`--replace` to explicitly target only this account's credential in the selected backend.
If that entry is absent, `--replace` creates it; if present, it updates it. A failed
replacement leaves the configured source unchanged. When the selected backend already
matches the configured source, imapledger does not rewrite the source; when they differ,
the source changes only after a successful replacement. It never switches to prompt mode
as an intermediate step. VaultConfig commits file-vault updates atomically. Keyring
operations depend on the backend's own multi-step guarantees, which may be weaker.

Setting a stored credential creates it in the secure backend before changing the config
source. If config persistence fails, imapledger attempts to remove only the credential it
just created. If that rollback also fails, the error reports a possible orphaned
credential. Deletion changes the config source to `prompt` before removing only the
current account's credential. If deletion fails, imapledger restores the previous source;
a failed restoration is reported as inconsistent state. Other credentials in a shared
vault are retained.

`auth status` never prompts for a password or unlocks the file vault. For keyring storage,
it reports backend availability and account credential presence when safely available. If
the keyring is unavailable, it shows a safe reason and installation hint. For vault
storage, it inspects the file without decrypting entries. It reports safe format and KDF
metadata; account-specific presence is `unknown until unlock`. `--verbose` includes the
vault format, KDF, memory and operation limits, entry count, and the current
`new-passphrase minimum` from local configuration. This minimum describes the policy for
future creation or passphrase changes, not the policy used to create an existing vault.
Status does not perform IMAP login.

A new vault prompts for the IMAP password and a separate master passphrase, confirmed
before the vault is created. The prompt shows the configured minimum. The
`[imap.auth].vault_min_passphrase_length` setting defaults to 12 characters unless changed;
it is a minimum character count, and digits or symbols do not alter the threshold. The
example above sets it to 10.

VaultConfig applies this minimum when it creates a vault and when `auth change-passphrase`
sets a new master passphrase. The minimum is not enforced while unlocking an existing vault.
Changing the setting does not rewrite a vault or prevent its existing passphrase from
unlocking it. The actual master passphrase is never written to TOML.

Lowering the default is a deliberate security tradeoff. Argon2id slows offline guessing,
but anyone with a copied encrypted vault can attack it offline. Adding digits or symbols
does not automatically make a shorter human-chosen passphrase equivalent to a longer one.
An OS keyring remains preferable when the operating system provides a suitable protected
backend. Do not lose the master passphrase, because the encrypted vault contents cannot be
recovered without it. It protects credentials at rest but does not protect against malware
already running with the same user's privileges.

`auth change-passphrase` is available only when the configured source is `vault`. It asks
for the current passphrase and a confirmed new passphrase, uses the configured vault path,
and changes neither the IMAP password nor `auth.source`. Passphrases are never printed or
stored in TOML. `auth delete` asks for confirmation unless `--yes` is supplied; vault mode
also asks for its master passphrase.

A missing or unavailable credential in an explicitly selected keyring or vault is an
error. imapledger does not silently fall back to a password prompt. `clean`, `doctor`,
legacy `rule learn`, `rule test`, and config-mode `folders` resolve credentials once per
invocation. Direct `folders --host ... --username ...` mode has no configured storage
source and continues to use hidden prompt authentication.

## Configuration ledger

The optional `[config_store]` section selects an existing IMAP folder for append-only configuration snapshots. Config-ledger commands load only `[imap]` and `[config_store]`, so they do not require `[spam]`. The configured store folder cannot be a cleaning source or move destination. `imapledger config show` remains an inspection of the effective local application configuration and never connects to IMAP. See the [configuration ledger guide](config-store.md) for setup, commands, history, secret handling, and retention limits.

Example:

```toml
[config_store]
folder = "INBOX.imapledger.Config"
max_file_bytes = 1048576
```

The folder must already exist. Snapshot messages are readable email, not encrypted secret storage.

## Legacy bare-clean compatibility configuration

This configuration supports the deprecated bare `clean` compatibility workflow and legacy category classification. It scans the listed `spam.folders` and routes SPAM, NOT_SPAM, and REVIEW outcomes to configured actions. Positional `clean FOLDER` instead uses the separate schema-2 `rules.toml` pipeline.

```toml
[imap]
host = "imap.example.org"
port = 993
username = "me@example.org"

[imap.auth]
source = "prompt"

[spam]
folders = ["INBOX.Junk", "INBOX.Spam"]
max_message_bytes = 2000000
max_body_chars = 20000

[spam.state]
backend = "imap-keywords"

[spam.actions.spam]
action = "move"
destination = "INBOX.Trash"

[spam.actions.not_spam]
action = "move"
destination = "INBOX.NotSpam"

[spam.actions.review]
action = "keep"

[spam.policy]
legitimate_veto_at = 0.80
phishing_delete_at = 0.90
identity_deception_at = 0.90
unsolicited_bulk_at = 0.92
delete_safe_at = 0.88
provider_junk_support_at = 0.80

[spam.authentication]
trusted_authserv_ids = []

[spam.provider]
trusted_spam_headers = []
```

`spam.folders`, when configured, lists compatibility and legacy classification source mailboxes, not destinations. It may be omitted when only positional routing is used. Bare `clean` processes them in listed order, one source-scoped IMAP session at a time. Its `--limit`, `--offset`, and `--sort` options apply independently in each source. Positional `clean FOLDER` scans only its named source, uses bounded UID windows, defaults to oldest-first, and does not accept `--offset`. UIDs from different folders are never compared.

Source mailbox names are exact and server-specific. Every configured source must exist and be selectable on the account. The example names above are not universal; imapledger does not normalize names or create source folders. `doctor` distinguishes a missing source from an existing source that cannot be selected.

## Classification state backend

The optional state backend is configured with `[spam.state].backend`:

```toml
[spam.state]
backend = "imap-keywords"
```

Supported values are `none` and `imap-keywords`. `imapledger init` selects `imap-keywords` for new configurations. Existing configurations that omit `[spam.state]` use `none` for backward compatibility. `imapledger config show` displays the effective setting. The application owns the marker names; they are not configurable.

The selected compatibility source must advertise persistent custom keywords through `PERMANENTFLAGS` (`\\*` or the exact keyword). `doctor` reports persistence support, and bare `clean --apply` checks it before classification whenever a configured outcome may be kept. Positional `clean FOLDER` does not use IMAP classification keywords. See [Persistent state](state.md) for marker semantics and the separate local progress database.

## Unified routing rules

The positional `clean FOLDER` pipeline reads schema-2 rules from the sibling `rules.toml`. The first enabled spam, semantic, or deterministic header rule that matches wins. Full mode routes unmatched messages to `rules.fallback_destination`; a fallback is required. `--rule ID` scans only one enabled rule and leaves non-matches in the source. `spam.folders` is optional and does not limit this explicit-folder path. Destinations are configured explicitly and must exist; preview is the default and `--apply` is required to move mail.

The schema-2 format supports `rules.default_match_at`, per-rule semantic descriptions and `match_at` thresholds, optional `source_folders`, and deterministic header matchers. Schema-1 header rules require explicit migration with `imapledger rule migrate --preview` followed by `--apply`; only MOVE rules migrate, and no fallback is inferred. See [Unified routing rules](rules.md) for the full schema and priority semantics.

## Legacy global classification actions

The existing policy verdicts are kept for compatibility. They map to three global classification categories and their configured actions:

| Policy verdict       | Classification category | Config table              |
| -------------------- | ----------------------- | ------------------------- |
| `SpamVerdict.DELETE` | spam                    | `[spam.actions.spam]`     |
| `SpamVerdict.KEEP`   | not-spam                | `[spam.actions.not_spam]` |
| `SpamVerdict.REVIEW` | review                  | `[spam.actions.review]`   |

These actions are global category mappings for legacy classification, not schema-2 routing rules. `imapledger mail classify --apply` and the legacy TUI classification path can apply the selected category's configured action to one message in any selectable mailbox folder. They retain exact-folder and UID confirmation and safety checks. The `spam.folders` list limits deprecated bare `clean` only. Positional `clean FOLDER` uses schema-2 rules and the full-pipeline fallback.
The NOT_SPAM action maps to `SpamVerdict.KEEP`; `REVIEW` is separate and follows `[spam.actions.review]`.
An action table accepts `keep`, `move`, or `delete`:

- `keep` leaves the message in its current source folder.
- `move` requires a non-empty `destination` naming an existing folder.
- `delete` permanently removes the message through the exact-UID deletion path. It is valid only for the spam outcome.

Not-spam and review outcomes cannot be configured for deletion. Review defaults to `keep`. Skipped messages and classification or policy errors always remain in the source folder, regardless of configured actions. A destination cannot equal any configured source folder. Folder names are preserved exactly, including spelling and case. Two outcomes may share a destination if configured explicitly.
With the plural `folders` schema, legacy category action outcomes omitted from the configuration default to `keep`. Permanent deletion in bare-clean compatibility therefore requires an explicit `[spam.actions.spam]` entry. Legacy scalar `spam.folder` configurations retain the old spam-delete default when action tables are absent.

`imapledger` does not create destinations. Configured moves require server support for the IMAP MOVE capability and never fall back to COPY and EXPUNGE. Legacy delete actions require UIDPLUS and exact-UID EXPUNGE.

Changing actions does not change spam-policy thresholds. The policy remains fail-closed, and a less destructive action does not make classification more aggressive.

## Discover server folder names

Mailbox names are server-specific. Discover the exact names before writing `spam.folders` or move destinations, using either direct connection options:

```bash
imapledger folders --host imap.example.org --username me@example.org
```

or an existing configuration:

```bash
imapledger folders --config /path/to/config.toml
```

The config mode needs only a valid `[imap]` table. `folders` does not validate or use `spam.folders`, so the spam section may be absent or incomplete. It resolves the configured credential source in config mode; direct mode continues to use hidden prompt authentication. The command connects over TLS and is read-only: one IMAP `LIST` discovers mailbox metadata, and optional `STATUS (MESSAGES UNSEEN)` requests provide aggregate counts without selecting mailboxes or fetching message contents. `--no-counts` skips STATUS requests entirely.

| Folder | Exact IMAP name |     Total |     Read |     Unread | Role        |
| ------ | --------------- | --------: | -------: | ---------: | ----------- |
| INBOX  | INBOX           | `<total>` | `<read>` | `<unread>` | Inbox       |
| Junk   | INBOX.Junk      | `<total>` | `<read>` | `<unread>` | Junk        |
| Shared | Shared          |         - |        - |          - | `\Noselect` |

The exact IMAP name column is the value to copy into configuration. Read is calculated as total minus unread. STATUS avoids an imapledger client-side scan through messages, but the server may perform internal work to calculate these counts. Use `--no-counts` when you only need names and flags.

## Create and inspect configuration

`init` writes the new plural-folder schema and explicit action tables. Source options can be repeated:

```bash
imapledger init \
  --host imap.example.org \
  --username me@example.org \
  --folder INBOX.Junk \
  --folder INBOX.Spam \
  --spam-action move \
  --spam-destination INBOX.Trash \
  --not-spam-action move \
  --not-spam-destination INBOX.NotSpam
```

Review the normalized, effective configuration with:

```bash
imapledger config show
imapledger config show --config /path/to/config.toml
```

The command prints the configuration path and TOML, including defaults in effect. It does not prompt for a password, connect to IMAP, or print credentials. It is inspection-only.

## Legacy configuration

A legacy configuration may use a scalar source:

```toml
[spam]
folder = "Spam"
```

When `spam.folders` is absent, `spam.folder` is accepted as a one-element source list and a deprecation warning is emitted. Configurations containing both `folder` and `folders` are rejected. Existing legacy files without action tables keep their old behavior: spam maps to `delete`, while not-spam and review map to `keep`. This preserves deletion behavior across the compatibility period. New files written by `init` or the configuration writer use `folders` and explicit action tables only.

Legacy `spam.threshold` values are warned about and ignored. Use the named values under `[spam.policy]`. When policy values are omitted, the documented defaults are used.
