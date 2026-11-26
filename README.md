# imapledger

imapledger is a security-scoped IMAP routing and configuration tool. `clean FOLDER` evaluates an ordered schema-2 rule pipeline and can resume bounded IMAP scans from durable local progress. The TUI provides rule development and exact-plan single-message testing. The semantic model never receives an IMAP client and cannot select destinations or issue IMAP commands.

## Security model

- Each `ScopedMailbox` session is bound to one source folder.
- Source folders are processed in configured order, one connection at a time.
- IMAP uses TLS and UID mode. The default credential source is hidden prompt authentication; optional OS keyring and encrypted-vault sources keep passwords out of configuration.
- IMAP uses TLS and UID mode. The default credential source is hidden prompt authentication; optional OS keyring and encrypted-vault sources keep passwords out of configuration.
- Positional `clean FOLDER` is preview-only by default. It scans one exact source folder in bounded UID windows, records local progress only when applying, and does not use `spam.folders` as its scope.
- `clean FOLDER --apply` uses only destinations configured in schema-2 rules. Destinations must exist, cannot be the source or reserved config-store folder, and require server MOVE support. imapledger does not create folders or fall back to COPY and EXPUNGE.
- Before `--apply`, the source and routing destinations are checked read-only. Every MOVE is bound to the exact source, UIDVALIDITY, UID, active rules, and configured destination. Preflight is best-effort, not transactional.
- Bare `clean` remains a deprecated compatibility workflow over `spam.folders`. It retains the older SPAM, NOT_SPAM, and REVIEW actions and classification-state keywords; it is separate from resumable routing.
- The semantic model evaluates message evidence only. Ordered rules, thresholds, and configured fallback own every destination and side effect.
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

Use exact IMAP names for source folders and destinations. `spam.folders` is optional for the explicit-folder pipeline and, when configured, remains the scope for deprecated bare `clean` compatibility. Legacy manual classification commands can target any selectable folder, and positional `clean FOLDER` can process any valid selectable source folder. The command uses IMAP `LIST` and aggregate `STATUS (MESSAGES UNSEEN)` counts. It does not select mailboxes or fetch message contents. `--no-counts` skips STATUS entirely. STATUS avoids a client-side scan through messages, although the server may do internal work to calculate mailbox counts.

Create a configuration file with repeated source folders and explicit actions:

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

These `[spam.actions.*]` settings apply to legacy category classification and deprecated bare `clean` compatibility. In that workflow, `SpamVerdict.DELETE`, `KEEP`, and `REVIEW` map to SPAM, NOT_SPAM, and REVIEW; REVIEW defaults to keep, and delete is supported only for SPAM. The new positional `clean FOLDER` workflow uses the ordered schema-2 routing rules and fallback instead. See [the unified rules guide](docs/rules.md).

Mailbox names are exact and server-specific. Every configured source must exist and be selectable on the account. The `INBOX.Junk` and `INBOX.Spam` names above are examples, not universal names. `doctor` distinguishes missing sources from existing sources that cannot be selected.
For the plural `folders` schema, omitted category action tables default to `keep`. Permanent deletion in the legacy classification workflow therefore requires an explicit `[spam.actions.spam]` entry. Legacy scalar `spam.folder` configurations retain the old spam-delete default when action tables are absent.

Legacy configurations with `spam.folder` remain supported with a deprecation warning. If they have no action tables, the old behavior is preserved: spam is deleted when `--apply` is used, and not-spam and review are kept. New configurations use `folders` and explicit action tables.

Legacy `spam.threshold` values are deprecated, warned about, and ignored. The documented policy defaults apply when `[spam.policy]` is absent. There is deliberately no password setting. Configure `pyjev` authentication separately as documented by `pyjev`.

The resumable routing pipeline is configured separately in the sibling `rules.toml`, using schema 2. It supports spam-policy, semantic, and deterministic header rules, plus a full-pipeline fallback destination. `spam.folders` is optional and does not constrain positional `clean FOLDER`. See [rules](docs/rules.md), [cleaning](docs/cleaning.md), and [progress state](docs/state.md).

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

```bash
imapledger folders --no-counts
imapledger clean INBOX.Junk --limit 10
imapledger clean INBOX.Junk --limit 10 --apply
imapledger clean INBOX.Junk --rule newsletters --apply
imapledger progress list
imapledger doctor
imapledger config show
```

`clean FOLDER` uses the resumable schema-2 pipeline. Preview is the default and does not advance the durable cursor. Apply evaluates enabled rules in priority order and moves the exact UID to the winning rule's destination or, in full mode, the configured fallback. `--rule ID` scans only one enabled rule. Full mode requires a fallback. Positional cleaning defaults to oldest-first; `--sort newest` reverses UID order. `--limit` bounds work in this invocation, and bounded UID windows avoid a full-mailbox UID snapshot.

Use `imapledger progress show FOLDER` to inspect a run, `progress errors FOLDER` to list retryable error codes, and `clean FOLDER --retry-errors --apply` to retry matching errors. `--new-run` explicitly supersedes active progress. See [the cleaning guide](docs/cleaning.md) for run identity, high-watermarks, UIDVALIDITY, and failure behavior.

Bare `imapledger clean` remains available temporarily with a deprecation warning. It uses the older category-action workflow and `spam.folders`; `--offset` is supported only there. Apply in either workflow is best-effort, not a transaction. Confirmed earlier changes are retained if a later message fails.

## Persistent classification state

Server-side IMAP keywords are legacy classification state for spam, not-spam, or review outcomes after an applied `keep` action. They are used by the deprecated bare-clean compatibility workflow, not by resumable positional routing. New routing progress is stored separately in a local SQLite database and tracks runs, UID cursors, and safe results. See the [state guide](docs/state.md) for both mechanisms and their distinct reset behavior.

```bash
imapledger state status
imapledger review list --limit 20
imapledger explain 43652 --folder INBOX.Junk
imapledger state reset --folder INBOX.Junk --uid 43652 --apply
```

## Mail review console

Launch `imapledger ui` for folder browsing, bounded plain-text message reading, routing analysis, and the unified Rules workbench. Press `c` to inspect the current plan, `R` to edit or test rules, and `a` to apply the displayed plan after exact-message confirmation. Browsing uses read-only mailbox access and `BODY.PEEK`; opening a message does not mark it seen, fetch remote images, or send images to a model. Press `i` to analyze embedded images explicitly. `I` offers remote image loading behind a cancel-default privacy warning and strict HTTPS, DNS/IP, redirect, timeout, and response-size checks. Visual assessments are informational and do not affect routing or mail actions. HTML is not rendered, attachments are not opened, and results are kept only in the current session. See the [interactive console guide](docs/ui.md) for navigation and privacy behavior.

The same services are available through composable commands:

```bash
imapledger mail list --folder INBOX.Junk --limit 50
imapledger mail show 43724 --folder INBOX.Junk
imapledger mail classify 43724 --folder INBOX.Junk
imapledger mail classify 43724 --folder INBOX.Junk --apply
```

`mail list` fetches bounded headers only. `mail show` reads bounded text without changing flags. `mail classify` is preview-only unless `--apply` is explicitly supplied; applying uses the category's global action and existing exact-folder, UID, and mailbox safety checks. Classification can target a message from any selectable folder. This manual category-action command is separate from the schema-2 routing rules and their progress. Bare `imapledger` continues to print help, including in non-interactive use.

## Unified routing rules

The schema-2 `rules.toml` file defines ordered spam-policy, semantic, and deterministic header rules for `clean FOLDER`. The first enabled match wins; if none matches in full mode, the configured fallback is used. A rule's destination is explicit configuration, never model output. Preview is read-only, `--apply` is required to move mail, and a single-rule scan is available with `--rule ID`.

```bash
imapledger clean INBOX --limit 10
imapledger clean INBOX --rule newsletter --limit 10
imapledger rule migrate --preview
imapledger rule migrate --apply
```

Schema-1 header rules require explicit migration. The migration retains safe MOVE rules as schema-2 header rules, but does not infer a fallback. The older `rule learn/list/show/remove/test` helpers are schema-1-only; after migration use the `R` TUI workbench or edit `rules.toml` directly. See [docs/rules.md](docs/rules.md) for schema, priority, thresholds, migration, and safety.

`imapledger/decisions.toml` defines one `spam-evidence` bundle with independent unsolicited-bulk, phishing/scam, identity-deception, legitimate/expected, and delete-safe questions. The classifier sends one structured state per message and validates every child probability. Operational UID data and raw authentication payloads are not sent as semantic evidence.

Local evidence extraction normalizes sender and reply identities, list and automation metadata, provider markers, Unicode display-name hints, and bounded URL hostnames. URL paths and query tokens are removed from model state and normal reports. Message-provided values are untrusted content, never instructions.

Authentication results remain untrusted unless an exact receiver `authserv-id` is explicitly configured under `[spam.authentication]`. Do not add guessed IDs. Generic spam headers remain soft evidence unless a trusted provider header is explicitly configured and the operator has verified that the provider inserts it. A passing SPF, DKIM, DMARC, or ARC result is identity evidence, not proof that a message is harmless.

The pure deterministic policy applies named thresholds. Strong legitimate/expected evidence vetoes the spam-safe path, phishing can qualify directly, and identity or unsolicited-bulk findings need corroboration. Provider and subject spam markers alone lead to REVIEW. Changing a configured action does not change policy thresholds.

## Troubleshooting and diagnostic privacy

Start with the read-only protocol probe:

```bash
imapledger doctor --verbose
```

For a failing positional run, use `imapledger clean FOLDER --verbose` to see safe IMAP operation progress, `progress show FOLDER` to inspect saved counters, and `progress errors FOLDER` to view retryable error codes. Use `--no-progress` to disable per-message rows and `--debug` for local traceback frames and exception class names. Neither option enables raw IMAP wire logging.

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
