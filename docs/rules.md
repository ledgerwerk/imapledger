# Unified routing rules

`rules.toml` uses schema 3 and defines one ordered routing system for batch runs, single-message evaluation, and learning. The first enabled rule that matches wins. Each rule owns an explicit destination. A model can provide evidence for a semantic decision, but cannot choose a folder or perform an IMAP action.

Rules apply to every selectable mail folder by default. `source_folders` is optional and restricts a rule when a narrower scope is needed or preserved from migration. Config Ledger is excluded as a routing source and destination.

## Rule types and matching

| Type       | Behavior                                                                                                                                                       |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spam`     | The built-in Spam rule matches only when the spam policy returns SPAM. NOT_SPAM and REVIEW continue to later rules.                                            |
| `semantic` | A matching `match_any` matcher gives a deterministic match. Otherwise the semantic evaluator compares the message with the required description and threshold. |
| `header`   | Matches deterministic message-header fields without a model call. At least one matcher is required.                                                            |

`match_any` is OR across matcher tables. Fields within one matcher are AND. Supported fields include `from_address`, `from_domain`, `return_path`, `return_path_domain`, `list_id`, `auto_submitted`, `subject`, and `subject_prefix`. Values are normalized where appropriate; subject comparisons are case-insensitive. There are no regular expressions or message-authored actions.

A semantic rule can combine deterministic learning with semantic matching. If any learned matcher matches, the rule matches without an unnecessary model request. Otherwise its description is evaluated at `match_at`, or `rules.default_match_at` when no per-rule threshold is set. The default threshold is `0.90`.

The built-in Spam identity uses ID `spam` and type `spam`. Its destination and enabled state can be configured, but the rule cannot be repurposed as another type or removed. Presets create common semantic rules; they do not invent destinations.

## No match and same-folder behavior

No fallback is required. If no rule matches, the message stays in its current folder. If the winning rule's destination is already the source folder, the result is ALREADY THERE and no MOVE is issued. Evaluation and preview do not mutate mail. Model or validation errors fail closed.

Schema-2 `fallback_destination` values are deprecated and ignored by schema 3. Migration reports that unmatched mail will stay in place. Do not recreate a fallback as an implicit catch-all rule.

## Configuration format

The default file is `$XDG_CONFIG_HOME/imapledger/rules.toml`, or `~/.config/imapledger/rules.toml` when `XDG_CONFIG_HOME` is unset. A custom `--config PATH` uses the sibling `rules.toml`.

```toml
[rules]
schema = 3
default_match_at = 0.90

[[rules.rule]]
id = "spam"
enabled = true
type = "spam"
destination = "INBOX.Trash"

[[rules.rule]]
id = "newsletters"
enabled = true
type = "semantic"
description = "Recurring mailing-list newsletters. Exclude account alerts and transactional receipts."
match_at = 0.93
destination = "INBOX.Newsletters"
match_any = [
  { list_id = "weekly.example.com" },
  { from_address = "newsletter@example.org" },
]

[[rules.rule]]
id = "delivery-status"
enabled = true
type = "header"
destination = "INBOX.System"
match_any = [{ from_address = "mailer-daemon@example.org", auto_submitted = "auto-replied" }]
```

Rules are evaluated in file order, from highest to lowest priority. `source_folders` is omitted for global scope. A semantic rule requires a description; a header rule requires at least one matcher; `match_at` is valid only for semantic rules. Destinations must already exist, cannot equal the source folder, and cannot be the Config Ledger folder.

## Rule management and exact-message evaluation

```bash
imapledger rule list
imapledger rule show newsletters
imapledger rule add receipts --type semantic --destination INBOX.Receipts \
  --description "Purchase receipts and order confirmations"
imapledger rule test newsletters --folder INBOX --uid 43724
imapledger rule evaluate --folder INBOX --uid 43724
imapledger rule learn newsletters --folder INBOX --uid 43724 --preview
```

`rule add` creates a global rule unless `--source-folder` is supplied. Repeat `--match field=value` to add OR alternatives. `rule test` evaluates one selected rule; `rule evaluate` evaluates the full rule order. Both are read-only and name an exact folder and UID.

Learning strengthens an existing semantic rule with one safe deterministic matcher. It assesses fit and generalization safety, checks duplicates and higher-priority conflicts, and requires an unchanged rules fingerprint before save. It adds only the matcher to the existing rule. Learning never moves the example message.

## Preview and apply

```bash
imapledger rule preview INBOX --limit 10 --sort oldest
imapledger rule preview --all-folders --limit 10
imapledger rule apply INBOX --limit 10
imapledger rule apply INBOX --rule newsletters --retry-errors
imapledger rule apply --all-folders --limit 10 --yes
```

Preview is read-only. Apply performs destination and source preflight and asks for confirmation unless `--yes` is supplied. A rule-scoped run evaluates only the named rule. `--new-run` supersedes active progress; `--retry-errors` is apply-only and uses the matching run's rules, scope, UIDVALIDITY, and ordering. All-folder runs omit non-selectable folders and Config Ledger.

Each action is tied to the exact folder, UID, UIDVALIDITY, current rule fingerprint, and configured destination. IMAP MOVE uses exact UIDs. Preflight is best-effort rather than transactional; confirmed earlier moves are not rolled back if a later message fails. Ambiguous MOVE results stop for reconciliation.

`clean FOLDER` remains a deprecated compatibility alias for `rule preview FOLDER` or `rule apply FOLDER`. It uses the same rule-run operation. There is no bare-folderless Clean workflow.

## Migration

Schema-1 and schema-2 files require explicit migration:

```bash
imapledger rule migrate --preview
imapledger rule migrate --apply
```

Schema-1 MOVE rules become header rules while retaining their matchers and source scopes. Schema-2 `match` becomes a one-item `match_any`; fallback destinations are dropped with a warning because unmatched mail is kept in place. Valid legacy Spam MOVE configuration can populate the built-in Spam rule. Migration does not invent a destination or convert an unsafe action. Review the preview and its warnings before applying.

## TUI workbench

Run `imapledger ui` and press `R` for the unified Rules workbench. It includes Spam, rule ordering, presets, editing, read-only tests, and migration. Select a message and press `c` to evaluate the current rules. Press `e` to explain that existing evaluation without running it again. `a` opens confirmation for the displayed MOVE plan; `l` starts preview-first learning for an existing semantic rule. See [Interactive console](ui.md).
