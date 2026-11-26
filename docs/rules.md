# Unified routing rules

The schema-2 `rules.toml` file defines one ordered routing pipeline for `clean FOLDER` and single-message analysis. Rules can match the spam policy, a semantic category, or deterministic message headers. The first enabled matching rule wins. A rule supplies a configured destination; neither message content nor a model can choose a folder or issue an IMAP command.

## Rule types and priority

Rules are evaluated in file order, from highest to lowest priority. Disabled rules are skipped. A rule may be limited to `source_folders`; if omitted, it applies to any source folder accepted by the command.

| Type       | Behavior                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spam`     | Matches only when the existing deterministic spam policy returns SPAM. NOT_SPAM and REVIEW do not match and continue to lower-priority rules.                                   |
| `semantic` | Compares the message with the rule's required natural-language `description`. Its probability must meet `match_at`, or `rules.default_match_at` when the rule has no threshold. |
| `header`   | Deterministically matches all fields in its `match` table. No model call is needed for header-only evaluation.                                                                  |

The evaluator bundles enabled spam and semantic questions into one semantic evaluation per message. Header rules are evaluated locally. A model result is evidence only. Ordered rules, thresholds, destinations, fallback, and local validation determine the route.

Semantic descriptions should define a category positively and distinguish it from adjacent categories. The default threshold is `0.90`; higher values require stronger model confidence. Rule-specific `match_at` values override the default.

Header matcher fields are `from_address`, `from_domain`, `return_path`, `return_path_domain`, `list_id`, `auto_submitted`, `subject`, and `subject_prefix`. Fields combine with AND. Address and domain values are normalized, subject equality and prefix matching are case-insensitive, and there are no expressions, regular expressions, or OR conditions.

## Fallback and scan modes

In a full run, if no rule matches, the message is routed to `rules.fallback_destination`. Full mode requires a configured fallback. In apply mode, successfully processed full-mode messages are moved to the winning rule's destination or the fallback destination.

A single-rule scan, such as `clean INBOX --rule newsletters`, evaluates only that enabled rule. A match plans a move to that rule's destination. A non-match has no destination and stays in the source folder. It does not use the fallback.

Every destination must be an existing mailbox, cannot be the current source folder, and cannot be the configured configuration-ledger folder. `clean --apply` checks destinations before scanning and validates each exact-UID MOVE. Preview is the default.

## Configuration format

The default file is `$XDG_CONFIG_HOME/imapledger/rules.toml`, or `~/.config/imapledger/rules.toml` when `XDG_CONFIG_HOME` is unset. A custom `--config PATH` uses a sibling `rules.toml`.

```toml
[rules]
schema = 2
default_match_at = 0.90
fallback_destination = "INBOX.Processed"

[[rules.rule]]
id = "spam"
enabled = true
type = "spam"
destination = "INBOX.Junk"

[[rules.rule]]
id = "newsletters"
enabled = true
type = "semantic"
description = "Recurring subscription newsletters and product updates sent to a mailing list. Exclude account notices and one-to-one correspondence."
match_at = 0.93
destination = "INBOX.Newsletters"
source_folders = ["INBOX"]

[[rules.rule]]
id = "delivery-status"
enabled = true
type = "header"
destination = "INBOX.System"
match = { from_address = "mailer-daemon@example.org", auto_submitted = "auto-replied" }
```

Rules must have unique lowercase IDs containing letters, digits, and hyphens. A semantic rule requires a non-empty description. `match_at` is a probability from 0 to 1 and is valid only for semantic rules. A header rule requires a non-empty `match` table. A rule destination is always an explicit folder name.

## Preview, apply, and progress

```bash
imapledger clean INBOX
imapledger clean INBOX --limit 10
imapledger clean INBOX --limit 10 --apply
imapledger clean INBOX --rule newsletters --limit 10
imapledger clean INBOX --rule newsletters --apply
```

Preview is read-only and does not advance the durable UID cursor. `--apply` performs only configured MOVE actions. Full runs require a fallback; single-rule runs require an enabled rule applicable to the source folder. Runs resume only when account, source, UIDVALIDITY, rules fingerprint, mode, scope, and sort direction match. See [Cleaning and diagnostics](cleaning.md) for cursor behavior, retrying errors, and progress commands.

## TUI workbench

Run `imapledger ui` and press `R` to open the unified Rules workbench. It supports creating and editing rules, enabling or disabling them, changing priority, setting the fallback, deleting rules, and read-only tests of the selected rule or complete pipeline. Testing shows each rule's result, the first matching winner, and the destination. Applying a message requires a separate confirmation tied to the displayed plan and exact message. See [Interactive console](ui.md).

## Migrate schema-1 header rules

Schema-1 files are not rewritten when read. Preview and explicitly apply the migration:

```bash
imapledger rule migrate --preview
imapledger rule migrate --apply
```

Use `--config PATH` when the configuration is not at its default location. Only schema-1 MOVE rules can be converted safely; migration stops if a rule uses another action. Existing source scopes and matchers are retained as schema-2 `header` rules. Migration does not infer a fallback, so configure `rules.fallback_destination` before a full run. Keep a backup of `rules.toml` before applying the migration.

The older `rule learn`, `rule list`, `rule show`, `rule remove`, and `rule test` helpers operate on schema-1 files. After migration, manage schema-2 rules in the TUI or edit the TOML directly. Do not use a schema-1 helper against a migrated file.
