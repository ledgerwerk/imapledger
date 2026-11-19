# Configuration

The default configuration path is `$XDG_CONFIG_HOME/imapledger/config.toml`, or `~/.config/imapledger/config.toml` when `XDG_CONFIG_HOME` is unset. The separate rules file is named `rules.toml` beside the selected config file. The IMAP password is never written to configuration. If `[imap.auth]` is omitted, credential resolution uses hidden prompt authentication, preserving existing behavior. Credential-consuming commands resolve once per invocation and reuse the credential across source folders.

## IMAP credential sources

`[imap.auth].source` accepts `prompt`, `keyring`, or `vault`. It selects where imapledger obtains the IMAP password, not where it is written in TOML. `imapledger config show` displays the selected source but never a password, vault passphrase, or ciphertext, and does not connect to IMAP.

```toml
[imap.auth]
source = "prompt"
```

Prompt mode is the compatibility default. Stored credentials are opt-in through `auth set`, which reads the IMAP password using hidden input and never accepts it as a command-line argument:

```bash
imapledger auth set
imapledger auth set --storage encrypted-file
imapledger auth status
imapledger auth delete
imapledger auth change-passphrase
```

`auth set` defaults to the OS keyring. `--storage vault` and its `--storage encrypted-file` alias select the encrypted VaultConfig file. A new encrypted file is stored at `$XDG_DATA_HOME/imapledger/credentials.enc`, or `~/.local/share/imapledger/credentials.enc` when `XDG_DATA_HOME` is unset. Creating it prompts for a hidden master passphrase twice. Install `imapledger[keyring]` to enable the optional keyring backend. Only supported native OS keyrings are accepted; an unavailable backend fails closed and never falls back to plaintext or prompt authentication.

An existing credential is not overwritten. Delete the configured credential first, then set a replacement with `--storage vault` when needed. `auth delete` asks for confirmation unless `--yes` is supplied; vault mode also asks for the master passphrase. It removes only the current account's entry and returns the configured source to `prompt`, leaving other entries in a shared encrypted vault intact. `auth status` reports only source availability and, for keyring storage, the backend name; vault status prompts for the master passphrase to check the account entry. `auth change-passphrase` is available when the configured source is `vault` and prompts for the old and confirmed new values. Forgetting the vault passphrase makes its contents unrecoverable.

A missing or unavailable credential in an explicitly selected keyring or vault is an error. imapledger does not silently fall back to a password prompt. `clean`, `doctor`, `rule learn`, `rule test`, and `folders` resolve credentials once per invocation. Direct `folders --host ... --username ...` mode has no configured storage source and continues to use hidden prompt authentication.

## Multi-folder routing example

This configuration scans two source folders and routes spam and not-spam outcomes to existing destination folders:

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

`folders` lists source mailboxes, not destinations. Sources are processed in listed order, one source-scoped IMAP session at a time. `--limit`, `--offset`, and `--sort` select messages independently in each source. UID values from different folders are not compared.

Source mailbox names are exact and server-specific. Every configured source must exist and be selectable on the account. The example names above are not universal; imapledger does not normalize names or create source folders. `doctor` distinguishes a missing source from an existing source that cannot be selected.

## Learned routing rules

Routing rules are stored separately from this configuration in `rules.toml` beside the selected config file. The default path follows the same XDG configuration directory as `config.toml`. A rule source must be one of the configured `spam.folders`; rules cannot add folders to the scan. Rule move destinations must exist and cannot be configured source folders.

The versioned format is:

```toml
[rules]
schema = 1

[[rules.rule]]
id = "mailer-daemon-gmx-net"
enabled = true
source_folders = ["INBOX.Junk"]
action = "move"
destination = "INBOX.Trash"
match = { from_address = "mailer-daemon@gmx.net" }
```

Rules support only `keep` and `move`. Matcher fields are combined with AND, and the first enabled match in file order wins. Supported fields are `from_address`, `from_domain`, `return_path`, `return_path_domain`, `list_id`, `auto_submitted`, `subject`, and `subject_prefix`. The file is strictly validated and written atomically with restrictive permissions. See [Learned routing rules](rules.md) for matching details and the command workflow.

## Outcome actions

The existing policy verdicts are kept for compatibility. Routing maps them separately:

| Policy verdict       | Routing outcome | Config table              |
| -------------------- | --------------- | ------------------------- |
| `SpamVerdict.DELETE` | spam            | `[spam.actions.spam]`     |
| `SpamVerdict.KEEP`   | not-spam        | `[spam.actions.not_spam]` |
| `SpamVerdict.REVIEW` | review          | `[spam.actions.review]`   |

A configured not-spam action runs only for `SpamVerdict.KEEP`; `REVIEW` is a separate outcome and follows `[spam.actions.review]`.
An action table accepts `keep`, `move`, or `delete`:

- `keep` leaves the message in its current source folder.
- `move` requires a non-empty `destination` naming an existing folder.
- `delete` permanently removes the message through the exact-UID deletion path. It is valid only for the spam outcome.

Not-spam and review outcomes cannot be configured for deletion. Review defaults to `keep`. Skipped messages and classification or policy errors always remain in the source folder, regardless of configured actions. A destination cannot equal any configured source folder. Folder names are preserved exactly, including spelling and case. Two outcomes may share a destination if configured explicitly.
With the new plural `folders` schema, action outcomes omitted from the configuration default to `keep`. Permanent deletion therefore requires an explicit `[spam.actions.spam]` entry. Legacy scalar `spam.folder` configurations retain the old spam-delete default when action tables are absent.

`imapledger` does not create destinations. Move actions require server support for the IMAP MOVE capability. They never fall back to COPY and EXPUNGE. Delete actions require UIDPLUS. A configuration using both move and delete actions requires both capabilities when applying actions.

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
