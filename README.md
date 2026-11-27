# imapledger

imapledger is a security-scoped IMAP routing and configuration tool. Schema-3 rules drive read-only preview, explicit apply, exact-message evaluation, and bounded learning. The TUI provides one Rules workbench and exact-message plan review. The semantic model never receives an IMAP client and cannot select destinations or issue IMAP commands.

## Security model

- Each `ScopedMailbox` session is bound to one source folder.
- Source folders are processed in configured order, one connection at a time.
- IMAP uses TLS and UID mode. The default credential source is hidden prompt authentication; optional OS keyring and encrypted-vault sources keep passwords out of configuration.
- IMAP uses TLS and UID mode. The default credential source is hidden prompt authentication; optional OS keyring and encrypted-vault sources keep passwords out of configuration.
- `rule preview` is read-only and processes a bounded folder scope, including an all-selectable-folders option. It does not mutate mail or per-message progress.
- `rule apply` uses only configured rule destinations. Destinations must exist, cannot be the source or Config Ledger, and require server MOVE support. No fallback is required; unmatched mail stays in place.
- Before apply, sources and destinations are checked read-only. Every MOVE is bound to the exact source, UIDVALIDITY, UID, current rules fingerprint, and configured destination. Preflight is best-effort, not transactional.
- `clean FOLDER` remains a deprecated adapter to the same rule-run operation. There is no separate bare Clean workflow.
- Processing errors fail closed. Confirmed earlier moves are not rolled back; ambiguous MOVE results stop the run for reconciliation.

A process with arbitrary code execution and the IMAP password could still create an unrestricted connection. Use a dedicated IMAP account and server-side ACLs where stronger isolation is needed.

## Install for development

```bash
git clone https://github.com/ledgerwerk/imapledger
cd imapledger
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

`setuptools_scm` derives the version from Git tags. There is intentionally no `src/` directory.

## Configure

Discover server-specific mailbox names before choosing source folders or move destinations:

```bash
imapledger folders \
  --host imap.example.org \
  --username me@example.org
```

Use exact IMAP names for source folders and destinations. `spam.folders` is optional for unified rules and does not define their source scope. The rule CLI accepts an explicit folder or `--all-folders`; Config Ledger and non-selectable folders are excluded. The `folders` command uses IMAP `LIST` and optional aggregate `STATUS (MESSAGES UNSEEN)` counts without selecting mailboxes or fetching message contents. `--no-counts` skips STATUS requests.

A compatibility configuration can retain category actions for `mail classify`; unified destinations are managed in `rules.toml`:

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

The default file is `$XDG_CONFIG_HOME/imapledger/config.toml`, or `~/.config/imapledger/config.toml` when `XDG_CONFIG_HOME` is unset. `init` never stores a password. `imapledger config show` prints the configuration path and normalized effective TOML without prompting or connecting to IMAP.

Select stored credentials without placing them in TOML or command arguments:

```bash
python -m pip install 'imapledger[keyring]'  # optional OS keyring support
imapledger auth set  # auto selects an available approved OS keyring
imapledger auth set --storage vault
imapledger auth set --storage keyring
imapledger auth set --storage vault --replace
imapledger auth status --verbose
imapledger auth delete
imapledger auth change-passphrase
```

See the [configuration guide](docs/configuration.md) for credential-source behavior, vault recovery limits, and deletion semantics.

`auth set` defaults to `--storage auto`: it probes an approved native OS keyring and fails
with explicit choices if none is usable. It never silently changes to the encrypted file
vault or prompt mode.

`--replace` is an explicit opt-in for replacing the current account's credential in the
selected backend. The vault uses a separate master passphrase, not an IMAP password or PIN.
It protects credentials at rest, but not against malware already running with the same
user's privileges.

The encrypted-file vault requires a minimum master-passphrase length of 12 characters by
default. Set a different minimum for new vaults and passphrase changes with
`[imap.auth].vault_min_passphrase_length`; it does not affect unlocking existing vaults.
For example:

```toml
[imap.auth]
source = "vault"
vault_path = "~/.local/share/imapledger/credentials.enc"
vault_min_passphrase_length = 10
```

This is a minimum character count, not a character-class rule. Lowering it is a deliberate
security tradeoff because a copied encrypted vault can be attacked offline. See the
[configuration guide](docs/configuration.md) for the policy details and security guidance.

Example configuration:

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
```

The `[spam.actions.*]` settings below belong to the legacy category-based `mail classify` compatibility command. Unified rule destinations are configured in the sibling `rules.toml`; `rule preview` and `rule apply` do not use category actions. See [the unified rules guide](docs/rules.md) for schema 3 and migration.

Mailbox names are exact and server-specific. Every configured source must exist and be selectable on the account. The `INBOX.Junk` and `INBOX.Spam` names above are examples, not universal names. `doctor` distinguishes missing sources from existing sources that cannot be selected.
For the plural `folders` schema, omitted category action tables default to `keep`. Permanent deletion in the legacy classification workflow therefore requires an explicit `[spam.actions.spam]` entry. Legacy scalar `spam.folder` configurations retain the old spam-delete default when action tables are absent.

Legacy configurations with `spam.folder` remain supported with a deprecation warning. If they have no action tables, the old behavior is preserved: spam is deleted when `--apply` is used, and not-spam and review are kept. New configurations use `folders` and explicit action tables.

Legacy `spam.threshold` values are deprecated, warned about, and ignored. The documented policy defaults apply when `[spam.policy]` is absent. There is deliberately no password setting. Configure `pyjev` authentication separately as documented by `pyjev`.

The unified routing rules live in the sibling `rules.toml`, using schema 3. Rules are global by default and may match Spam policy, semantic descriptions, or deterministic headers. `match_any` supports multiple deterministic alternatives. No fallback is required; unmatched mail stays in place. `spam.folders` does not constrain rule preview or apply. See [rules](docs/rules.md), [rule runs and progress](docs/cleaning.md), and [state](docs/state.md).

## Configuration ledger

Store small UTF-8 configuration files for arbitrary tools as append-only, readable email snapshots in a dedicated IMAP folder. Configure `[config_store]` locally, then use `config push`, `list`, `versions`, `diff`, `pull`, or `cat`. The store folder must already exist. Without `[config_store]`, `config list` exits successfully with a disabled-store message; commands that access the remote store report an actionable configuration error. Snapshots are not encrypted, and the secret scan is best-effort. See the [configuration ledger guide](docs/config-store.md) for setup, history, overwrite behavior, and security limits.

```bash
imapledger config push ruff ~/.config/ruff/ruff.toml
imapledger config list
imapledger config versions ruff
imapledger config diff ruff --direction local-to-imap
imapledger config pull ruff
```

## Dry run and apply

````bash
```bash
imapledger rule preview INBOX.Junk --limit 10
imapledger rule preview --all-folders --limit 10
imapledger rule apply INBOX.Junk --limit 10
imapledger rule apply --all-folders --limit 10
imapledger progress list
imapledger doctor
imapledger config show
````

`rule preview` evaluates the ordered schema-3 rules without changing mail or per-message progress. `rule apply` asks for confirmation by default, validates destinations, and moves exact UIDs. No match keeps mail in place, and a destination equal to the current folder needs no MOVE. `--rule ID` narrows evaluation to one enabled rule. `--limit`, `--sort`, `--new-run`, and apply-only `--retry-errors` control bounded progress. Use `--all-folders` to process every selectable folder except Config Ledger.

Use `imapledger progress show FOLDER` to inspect a run, `progress errors FOLDER` to list retryable error codes, and `rule apply FOLDER --retry-errors` to retry matching errors. `--new-run` explicitly supersedes active progress. See [the cleaning guide](docs/cleaning.md) for run identity, high-watermarks, UIDVALIDITY, and failure behavior.

`imapledger clean FOLDER` remains temporarily as a deprecated adapter to `rule preview` or `rule apply` on one folder. It has no separate behavior tree. Apply is best-effort, not a transaction; confirmed earlier moves are retained if a later message fails.

## Persistent classification state

Server-side IMAP keywords are retained only for legacy category classification state after a `keep` action. The unified rule runner does not read or write them. Rule-run progress is stored separately in a local SQLite database and tracks runs, UID cursors, and safe outcomes. See the [state guide](docs/state.md) for both mechanisms and their distinct reset behavior.

```bash
imapledger state status
imapledger review list --limit 20
imapledger explain 43652 --folder INBOX.Junk
imapledger state reset --folder INBOX.Junk --uid 43652 --apply
```

## Mail review console

Launch `imapledger ui` for folder browsing, rule evaluation, learning, batch preview/apply, and the unified Rules workbench. Press `c` to evaluate the selected message, `e` to explain the existing evaluation without rerunning, `R` to manage rules, and `a` to apply the displayed plan after exact-message confirmation. Browsing uses read-only mailbox access and `BODY.PEEK`; opening a message does not mark it seen or fetch remote images. `i` analyzes embedded images explicitly; `I` offers remote image loading behind a cancel-default privacy warning and strict network checks. Visual assessments are informational and do not affect routing. See the [interactive console guide](docs/ui.md) for navigation and privacy behavior.

The same services are available through composable commands:

```bash
imapledger mail list --folder INBOX.Junk --limit 50
imapledger mail show 43724 --folder INBOX.Junk
imapledger mail classify 43724 --folder INBOX.Junk
imapledger mail classify 43724 --folder INBOX.Junk --apply
```

`mail list` fetches bounded headers only. `mail show` reads bounded text without changing flags. `mail classify` is a legacy category-action compatibility command, preview-only unless `--apply` is supplied. It applies the configured action to one exact message in a selectable folder. New rule workflows use `rule test`, `rule evaluate`, and `rule apply` instead. Bare `imapledger` prints help, including in non-interactive use.

## Unified routing rules

The sibling `rules.toml` schema 3 defines ordered rules for Spam, semantic categories, and deterministic headers. Rules are global by default; `source_folders` can narrow a rule. `match_any` supports multiple OR alternatives, with AND fields inside each matcher. The first enabled match wins. No fallback is required, and no match keeps mail in place.

```bash
imapledger rule list
imapledger rule preview INBOX.Junk --limit 10
imapledger rule preview --all-folders --limit 10
imapledger rule apply INBOX.Junk --limit 10
imapledger rule evaluate --folder INBOX.Junk --uid 43724
imapledger rule migrate --preview
```

`rule preview` is read-only. `rule apply` requires confirmation unless `--yes`; it preflights destinations and acts only on the exact UIDs named by the current plan. Schema-1 and schema-2 rule files require explicit migration. Schema-2 fallback destinations are dropped with a warning rather than converted to catch-all moves. `clean FOLDER` is a deprecated adapter to rule preview/apply. See [docs/rules.md](docs/rules.md) for configuration, learning, migration, and safety.

`imapledger/decisions.toml` defines one `spam-evidence` bundle with independent unsolicited-bulk, phishing/scam, identity-deception, legitimate/expected, and delete-safe questions. The classifier sends one structured state per message and validates every child probability. Operational UID data and raw authentication payloads are not sent as semantic evidence.

Local evidence extraction normalizes sender and reply identities, list and automation metadata, provider markers, Unicode display-name hints, and bounded URL hostnames. URL paths and query tokens are removed from model state and normal reports. Message-provided values are untrusted content, never instructions.

Authentication results remain untrusted unless an exact receiver `authserv-id` is explicitly configured under `[spam.authentication]`. Do not add guessed IDs. Generic spam headers remain soft evidence unless a trusted provider header is explicitly configured and the operator has verified that the provider inserts it. A passing SPF, DKIM, DMARC, or ARC result is identity evidence, not proof that a message is harmless.

The pure deterministic policy applies named thresholds. Strong legitimate/expected evidence vetoes the spam-safe path, phishing can qualify directly, and identity or unsolicited-bulk findings need corroboration. Provider and subject spam markers alone lead to REVIEW. Changing a configured action does not change policy thresholds.

## Troubleshooting and diagnostic privacy

Start with the read-only protocol probe:

```bash
imapledger doctor --verbose
```

For a failing rule run, use `imapledger rule preview FOLDER --verbose` or `rule apply FOLDER --verbose` to see safe IMAP operation progress. `progress show FOLDER` reports saved counters, and `progress errors FOLDER` lists retryable error codes. Diagnostics do not include passwords, authentication payloads, exception messages, raw server responses, or message bytes.

Errors include safe context such as the configured folder, selector, UID range, batch, and recognized server status token. They do not print passwords, authentication payloads, exception messages, raw server responses, or message bytes. Verbose output and reports can still reveal folder names, account identifiers, UIDs, senders, and subjects, so redact those details before sharing.

The offline examples in `eval/spam_cases.jsonl` are synthetic and do not include real message bodies or recipient data.

## Tests and builds

```bash
pytest
ruff check .
sphinx-build -W docs docs/_build/html
python -m build
python -m twine check dist/*
```

All tests are offline and use fake IMAP and classifier implementations. The invariant remains: **models judge content; deterministic code owns permissions and side effects.**
