# Configuration

The default configuration path is `$XDG_CONFIG_HOME/imapledger/config.toml`, or `~/.config/imapledger/config.toml` when `XDG_CONFIG_HOME` is unset. The unified schema-4 rules file is named `rules.toml` beside the selected config file. The IMAP password is never written to configuration. If `[imap.auth]` is omitted, credential resolution uses hidden prompt authentication. Rule preview, apply, and exact-message operations resolve credentials once per invocation; rule management and migration previews are local operations.

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
`rule preview`, `rule apply`, `rule evaluate`, `rule test`, `rule learn`, `doctor`, and config-mode `folders` resolve credentials once per invocation. Rule list/show/add/edit/remove and migration preview are local operations. Direct `folders --host ... --username ...` mode has no configured storage source and continues to use hidden prompt authentication.

## Configuration ledger

The optional `[config_store]` section selects an existing IMAP folder for append-only configuration snapshots. The store is separate from local imapledger settings and ordered mail rules. `config show` is local-only and never connects to IMAP. Without `[config_store]`, `config list` reports that the store is disabled, while remote-store commands report an actionable configuration error. Snapshots are readable email, not encrypted secret storage. See the [configuration ledger guide](config-store.md).

```toml
[config_store]
folder = "INBOX.imapledger.Config"
max_file_bytes = 1048576
```

The folder must already exist. It cannot be used as a routing source or move destination.

## Generic message limits

`[mail]` contains optional, non-Spam processing limits. Defaults are 2,000,000 bytes per message and 20,000 body characters:

```toml
[mail]
max_message_bytes = 2000000
max_body_chars = 20000
```

Both settings must be positive integers. The table can be omitted when the defaults are suitable.

## Rules configuration

All automated mail behavior belongs in the sibling `rules.toml`, which uses schema 4. A minimal rule file can be created from a recipe or edited directly:

```toml
[rules]
schema = 4
default_match_at = 0.90

[[rules.rule]]
id = "spam"
enabled = true
type = "recipe"
recipe = "spam"
action = "move"
destination = "INBOX.Junk"
source_folders = ["INBOX"]
```

Rules are ordered, global by default, and do nothing when no rule matches. No rule is created automatically. Actions are `move`, `keep`, or `delete`; `move` requires an existing destination, and `keep` or `delete` must not specify one. Delete requires explicit authorization when applying. See [Unified routing rules](rules.md) for matching, recipes, trusted evidence, action safety, and examples.

Connection setup is independent of rule setup:

```bash
imapledger init --host imap.example.org --username me@example.org
imapledger rule recipe list
imapledger rule recipe add spam --destination INBOX.Junk
imapledger config show
```

`init` writes only IMAP connection and authentication settings. It does not create folders or rules. Use exact, server-specific mailbox names. Discover them with `imapledger folders --config /path/to/config.toml` or `imapledger folders --host imap.example.org --username me@example.org`.

## Removed Spam configuration and explicit migration

Normal configuration loading rejects a legacy `[spam]` table and directs you to the explicit migration command. Do not remove the table manually before reviewing the migration if you want to preserve its supported values:

```bash
imapledger rule migrate --preview
imapledger rule migrate --apply
```

The preview does not write files. Review the converted schema and every warning before applying. Migration can convert an explicitly configured legacy Spam action into an ordinary Spam / scam recipe rule, including its destination, source-folder scope, supported thresholds, and trusted evidence. If no legacy Spam action is configured, migration does not create a Spam rule. If rule ID `spam` already names an incompatible rule in the target file, resolve that ID conflict before migrating. Legacy `not_spam` and `review` actions are not migrated automatically. Create ordinary rules yourself for any desired non-Spam behavior.

If the preview includes a Delete rule, apply migration with `--allow-delete` as an explicit authorization to write a configuration that contains that rule:

```bash
imapledger rule migrate --apply --allow-delete
```

This migration authorization does not delete messages. A future mailbox run that applies a Delete action separately requires `imapledger rule apply ... --allow-delete`. Existing IMAP keywords and messages are not changed by configuration migration. Rules schemas 1, 2, and 3 also require explicit conversion; see [rule migration](rules.md#explicit-migration).
