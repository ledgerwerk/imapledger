# imapledger

A security-scoped IMAP automation tool. `imapledger` scans configured source folders, classifies messages using `pyjev` evidence, then maps deterministic policy outcomes to configured mailbox actions. The semantic model never receives an IMAP client and cannot select destinations or issue IMAP commands.

## Security model

- Each `ScopedMailbox` session is bound to one source folder.
- Source folders are processed in configured order, one connection at a time.
- IMAP uses TLS and UID mode. The default credential source is hidden prompt authentication; optional OS keyring and encrypted-vault sources keep passwords out of configuration.
- Dry-run is the default. It selects each source read-only and performs no mutations.
- `--apply` uses only configured actions. Every MOVE destination is allow-listed, must exist, and requires server MOVE support. imapledger does not create folders or fall back to COPY and EXPUNGE.
- Before `--apply`, all configured sources are checked read-only for authentication, required capabilities, exact source existence, SELECT, and move destinations. A failed preflight aborts before classifier construction or mutation. It is best-effort, not transactional, and server state can change before mutation-time checks.
- Moves and deletes use only UIDs from the initial source snapshot. Before mutation, imapledger rechecks UIDVALIDITY and confirms that the selected UIDs still exist.
- Permanent deletion is available only as an explicit spam action. It requires UIDPLUS and uses exact-UID EXPUNGE.
- Classification, evidence, and policy errors fail closed. Skipped and errored messages remain in their source folders.
- Separate source-folder operations are not one cross-folder transaction. If a later source fails, earlier confirmed changes are reported and are not rolled back.

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

Copy the exact IMAP name column into `spam.folders` or an action `destination`. The command uses IMAP `LIST` and aggregate `STATUS (MESSAGES UNSEEN)` counts. It does not select mailboxes or fetch message contents. `--no-counts` skips STATUS entirely. STATUS avoids a client-side scan through messages, although the server may do internal work to calculate mailbox counts.

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

The source folders are scanned in listed order. A `SpamVerdict.DELETE` maps to the spam outcome, `SpamVerdict.KEEP` maps to not-spam, and `SpamVerdict.REVIEW` maps to review. Configuration selects the action for each outcome. REVIEW defaults to keep. Skip and error results always keep. Delete is supported only for spam. Move destinations must already exist and cannot be any configured source folder.

Mailbox names are exact and server-specific. Every configured source must exist and be selectable on the account. The `INBOX.Junk` and `INBOX.Spam` names above are examples, not universal names. `doctor` distinguishes missing sources from existing sources that cannot be selected.
For the new plural `folders` schema, omitted action tables default to `keep`. Permanent deletion therefore requires an explicit `[spam.actions.spam]` entry. Legacy scalar `spam.folder` configurations retain the old spam-delete default when action tables are absent.

Legacy configurations with `spam.folder` remain supported with a deprecation warning. If they have no action tables, the old behavior is preserved: spam is deleted when `--apply` is used, and not-spam and review are kept. New configurations use `folders` and explicit action tables.

Legacy `spam.threshold` values are deprecated, warned about, and ignored. The documented policy defaults apply when `[spam.policy]` is absent. There is deliberately no password setting. Configure `pyjev` authentication separately as documented by `pyjev`.

## Dry run and apply

```bash
imapledger folders --no-counts
imapledger clean
imapledger clean --limit 10
imapledger clean --limit 10 --offset 10 --sort newest
imapledger clean --no-progress
imapledger clean --apply
imapledger doctor
imapledger config show
```

Each `clean` and `doctor` invocation resolves one IMAP credential and reuses it across configured source folders. The default prompt source asks once; keyring and vault sources use their configured secure backend.
Apply mode first checks every configured source and move destination read-only; if any preflight check fails, it stops before classifier construction or mutations. This is not a transaction and does not prevent server-side changes or runtime partial failures after preflight.

`--limit` and `--offset` apply independently to each source folder. With two folders, `--limit 10 --offset 10` selects positions 11 through 20 in each folder. `--sort newest` and `--sort oldest` order each folder by descending or ascending IMAP UID, which represents mailbox arrival order, not the message `Date:` header. UIDs are folder-local and are never globally ordered or merged.

Moves require the IMAP MOVE capability and an existing destination. Deletes require UIDPLUS. `doctor` checks every configured source, the configured action capabilities, and all move destinations without mutating mail. Mutation batches stop on failure. Earlier confirmed actions remain applied, later action groups and source folders are not attempted, and the command exits non-zero. Inspect pending UIDs before retrying because their result was not confirmed.

See [the configuration guide](docs/configuration.md), [the cleaning guide](docs/cleaning.md), and [the learned routing rules guide](docs/rules.md) for the complete schema, safety checks, reporting, and failure behavior.

## Learned routing rules

Use a routing rule for a personal mailbox preference that should remain separate from spam classification. For example, learn a narrow rule from one explicitly scoped message UID:

```bash
imapledger rule learn 43627 --folder INBOX.Junk --move INBOX.Trash --preview
imapledger rule learn 43627 --folder INBOX.Junk --move INBOX.Trash
imapledger rule list
imapledger rule test mailer-daemon-gmx-net --limit 20
```

Learning requires a configured source folder and an explicit move destination. Jev selects only from deterministic matcher candidates generated locally by imapledger; it cannot invent a matcher or destination. The message body is excluded from Jev's learning state by default. A proposal must pass local safety thresholds before it can be saved. `--preview` does not save, and the default save prompt is no. `--yes` confirms saving only. Moving the example message requires the separate `--apply-current` option.

Saved rules run before spam classification and are matched locally. A matching rule bypasses classification for that message, while non-matches continue through the existing spam policy. Rules are limited to configured source folders and cannot change REVIEW behavior for other messages. `clean` remains read-only unless `--apply` is supplied. See [docs/rules.md](docs/rules.md) for the schema, precedence, and safety details.

## Evidence and policy

`imapledger/decisions.toml` defines one `spam-evidence` bundle with independent unsolicited-bulk, phishing/scam, identity-deception, legitimate/expected, and delete-safe questions. The classifier sends one structured state per message and validates every child probability. Operational UID data and raw authentication payloads are not sent as semantic evidence.

Local evidence extraction normalizes sender and reply identities, list and automation metadata, provider markers, Unicode display-name hints, and bounded URL hostnames. URL paths and query tokens are removed from model state and normal reports. Message-provided values are untrusted content, never instructions.

Authentication results remain untrusted unless an exact receiver `authserv-id` is explicitly configured under `[spam.authentication]`. Do not add guessed IDs. Generic spam headers remain soft evidence unless a trusted provider header is explicitly configured and the operator has verified that the provider inserts it. A passing SPF, DKIM, DMARC, or ARC result is identity evidence, not proof that a message is harmless.

The pure deterministic policy applies named thresholds. Strong legitimate/expected evidence vetoes the spam-safe path, phishing can qualify directly, and identity or unsolicited-bulk findings need corroboration. Provider and subject spam markers alone lead to REVIEW. Changing a configured action does not change policy thresholds.

## Troubleshooting and diagnostic privacy

Start with the read-only protocol probe:

```bash
imapledger doctor --verbose
```

For a failing clean run, use `imapledger clean --verbose` to see safe IMAP operation progress. Use `--no-progress` to disable per-message rows and `--debug` for local traceback frames and exception class names. Neither option enables raw IMAP wire logging.

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
