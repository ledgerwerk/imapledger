# imapledger

imapledger is a security-scoped IMAP routing tool. Schema-4 ordered rules are the only mail automation model. A rule can use deterministic header matching, semantic matching, or a shared recipe, and its action is `move`, `keep`, or `delete`. No rules means no automatic mail actions.

## Safety model

- Rules run in file order. The first enabled matching rule wins. If no rule matches, mail stays in its current folder.
- `rule preview` and exact-message evaluation are read-only. `rule apply` uses exact source-folder UIDs after read-only preflight.
- Delete rules require explicit `--allow-delete` on apply, in addition to the normal apply confirmation. `--yes` only skips the confirmation prompt.
- Mailbox sessions are bound to one source folder. Actions are checked against UIDVALIDITY, the current rules fingerprint, the exact UID, and the configured action. Preflight is best-effort, not transactional.
- Destinations must already exist. Moves require IMAP MOVE support. imapledger does not create folders or fall back to COPY and EXPUNGE.
- The semantic model receives message evidence only. Deterministic code controls rule order, permissions, destinations, and IMAP operations.

A process with arbitrary code execution and the IMAP password could still create an unrestricted connection. Use a dedicated IMAP account and server-side ACLs when stronger isolation is needed.

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

Discover exact server-side folder names before using them as rule sources or move destinations:

```bash
imapledger folders --host imap.example.org --username me@example.org
```

Create connection settings only. `init` does not create folders or rules:

```bash
imapledger init --host imap.example.org --username me@example.org
imapledger config show
```

The default configuration path is `$XDG_CONFIG_HOME/imapledger/config.toml`, or `~/.config/imapledger/config.toml` when `XDG_CONFIG_HOME` is unset. `rules.toml` is stored beside the selected config file. `init` never stores a password. The minimal configuration is:

```toml
[imap]
host = "imap.example.org"
port = 993
username = "me@example.org"

[imap.auth]
source = "prompt"
```

Optional generic message limits belong in `[mail]`, not in a Spam section:

```toml
[mail]
max_message_bytes = 2000000
max_body_chars = 20000
```

See [configuration](docs/configuration.md) for credential sources, vault recovery limits, generic settings, and explicit migration of old configuration.

### Credentials

Credential resolution defaults to hidden prompt authentication. The IMAP password is never stored in TOML or accepted as a command-line argument. Stored credentials are opt-in:

```bash
python -m pip install 'imapledger[keyring]'  # optional OS keyring support
imapledger auth set
imapledger auth set --storage vault
imapledger auth status --verbose
imapledger auth change-passphrase
imapledger auth delete
```

`auth set` defaults to `--storage auto`, which uses an approved native OS keyring when available and otherwise fails with explicit options. It does not silently choose a file vault or prompt mode. The encrypted file vault uses a separate master passphrase and protects credentials at rest, not against malware running as the same user.

## Ordered rules and recipes

Rules are global unless `source_folders` narrows their scope. The rule ID is an ordinary identifier with no special meaning. A rule named `spam` is editable and removable like any other rule. No Spam rule is created during initialization or startup.

The shared recipe catalog is available from the CLI and the TUI:

```bash
imapledger rule recipe list --search spam
imapledger rule recipe show spam
imapledger rule recipe add spam --id spam --destination INBOX.Junk --source-folder INBOX
imapledger rule list
imapledger rule show spam
```

The Spam / scam recipe is an ordinary recipe rule. It preserves a conservative multi-signal detector using signals for unsolicited bulk, phishing or scams, identity deception, legitimate or expected mail, and safe automation. Strong legitimate evidence vetoes a match, and uncertain evidence is a non-match that allows later rules to run. Trusted authentication and provider evidence are used only when explicitly configured. The recipe has editable threshold options. Provider Spam markers alone are not sufficient to match.

Example `rules.toml`:

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

[rules.rule.options]
legitimate_veto_at = 0.80
phishing_match_at = 0.90

[[rules.rule]]
id = "delivery-status"
enabled = true
type = "header"
action = "move"
destination = "INBOX.System"
match_any = [{ from_address = "mailer-daemon@example.org" }]
```

Rules are evaluated from top to bottom. `match_any` is OR across matcher tables, and fields inside one matcher are AND. Semantic rules use a description and optional `match_at` threshold. Header rules use deterministic fields without a model call. Recipe rules use the shared catalog. A matching `keep` action is terminal, just like `move` and `delete`.

Trusted evidence is configured in the rules file only after verifying the exact receiver or provider:

```toml
[rules.evidence]
trusted_authserv_ids = ["mx.example.org"]
trusted_provider_headers = ["X-Verified-Junk"]
```

See [unified rules](docs/rules.md) for the complete schema, matching, recipe options, learning, and migration behavior.

## Preview and apply

```bash
imapledger rule preview INBOX --limit 10
imapledger rule preview --all-folders --limit 10
imapledger rule evaluate --folder INBOX --uid 43724
imapledger rule apply INBOX --limit 10
imapledger rule apply --all-folders --limit 10
imapledger progress list
imapledger doctor
```

Preview does not change mail. Apply asks for confirmation by default, checks destinations, and applies the current rule plan to exact UIDs. Use `--rule ID` to evaluate one enabled rule. `--all-folders` skips non-selectable folders and Config Ledger. `--allow-delete` is required only when applying a configured Delete action. `clean FOLDER` remains a deprecated alias for preview or apply on one folder.

The local SQLite progress database records resumable runs and safe per-UID outcomes. It defaults to `$XDG_STATE_HOME/imapledger/progress.sqlite3`, or `~/.local/state/imapledger/progress.sqlite3` when `XDG_STATE_HOME` is unset. See [rule runs](docs/cleaning.md) and [state and progress](docs/state.md).

## Migrate older configuration

Normal runtime configuration no longer accepts `[spam]`. Run explicit migration to inspect older schema-1 through schema-3 rule files and legacy Spam configuration:

```bash
imapledger rule migrate --preview
imapledger rule migrate --apply
```

Migration previews do not write files. Review every warning before applying. Legacy `not_spam` and `review` category actions are not recreated automatically. Legacy source folders and Spam policy/evidence settings are converted where applicable. If the preview proposes a Delete rule, applying that migration also requires `--allow-delete`; this authorizes creation of the rule and does not delete mail. Any later mailbox deletion still needs `rule apply --allow-delete`.

## Configuration ledger and interactive console

The optional Config Ledger stores readable snapshots of small configuration files in an existing IMAP folder. Snapshots are not encrypted and are not a secret store. See [configuration ledger](docs/config-store.md).

Launch `imapledger ui` for mailbox browsing, rule evaluation, batch preview/apply, progress, diagnostics, and the Rules workbench. Press `R` to manage ordinary rules and browse the searchable, category-filtered recipe catalog. The workbench supports scope, actions, recipe options, TOML preview, ordering, tests, migration, and confirmed rule removal. System setup edits connection and credential settings only. See [interactive console](docs/ui.md).

## Troubleshooting and privacy

Start with the read-only protocol probe:

```bash
imapledger doctor --verbose
```

Diagnostics do not include passwords, raw authentication payloads, exception messages, raw server responses, or message bytes. Verbose output and reports can still reveal folder names, account identifiers, UIDs, senders, and subjects, so redact them before sharing. Remote images are not fetched automatically by the TUI.

The offline examples in `eval/spam_cases.jsonl` are synthetic. Tests use fake IMAP and classifier implementations.
