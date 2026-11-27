# Unified routing rules

`rules.toml` uses schema 4 for batch runs, exact-message evaluation, and learning. It is the only user-facing mail automation configuration. Rules run in file order, and the first enabled matching rule wins. If no rule matches, mail remains in its current folder.

Rules apply to all selectable source folders by default. Set `source_folders` to restrict one rule. Config Ledger is excluded from routing sources and destinations. Rule IDs are ordinary identifiers: `id = "spam"` has no reserved behavior and can be edited, reordered, disabled, or removed. An absent or empty rules file creates no rule and performs no automatic action.

## Rule types and actions

| Type | Behavior |
| --- | --- |
| `semantic` | Match a description using the semantic evaluator and optional `match_at` threshold. Safe deterministic matchers can also be attached. |
| `header` | Match deterministic message-header fields without a model call. At least one matcher is required. |
| `recipe` | Use a named evaluator from the shared recipe catalog, optionally with recipe-specific options. |

A rule action is one of:

- `move` requires an existing `destination` mailbox.
- `keep` terminates evaluation and leaves the message in its current folder.
- `delete` permanently removes the message only after explicit apply-time authorization.

No action or destination is inferred from the rule ID. The model can provide evidence for matching, but cannot choose an action or destination or perform an IMAP operation.

`match_any` is OR across matcher tables. Fields within one matcher are AND. Supported matcher fields include `from_address`, `from_domain`, `return_path`, `return_path_domain`, `list_id`, `auto_submitted`, `subject`, and `subject_prefix`. Values are normalized where appropriate, and subject comparisons are case-insensitive. There are no regular expressions or message-authored actions.

Semantic rules can combine `match_any` with a required description. If a deterministic matcher matches, it can match without an unnecessary model request. Otherwise the semantic evaluator uses `match_at`, or `rules.default_match_at` when `match_at` is omitted. The default threshold is `0.90`.

## Recipe catalog and Spam / scam

The same searchable, category-filtered recipe catalog is used by the CLI and TUI:

```bash
imapledger rule recipe list
imapledger rule recipe list --category Safety
imapledger rule recipe list --search spam
imapledger rule recipe show spam
imapledger rule recipe add spam --id spam --destination INBOX.Junk
```

Recipes materialize ordinary ordered rules. The recipe ID (`spam`) identifies the evaluator; the rule ID is a user-selected identifier with no special meaning. No Spam rule is created automatically. The Spam / scam recipe is a conservative multi-signal detector, not a single semantic question. It combines unsolicited-bulk, phishing/scam, identity-deception, legitimate/expected, and safe-automation signals with trusted authentication and provider evidence. Strong legitimate evidence vetoes a match. Phishing can match at high confidence; identity deception, bulk mail, and provider evidence need corroboration. Uncertain evidence is a non-match, so later rules can run. Provider or subject markers alone do not match.

The recipe exposes threshold options including `legitimate_veto_at`, `phishing_match_at`, `identity_deception_at`, `unsolicited_bulk_at`, `action_safe_at`, and `provider_junk_support_at`. Defaults are conservative. Use `rule recipe show spam` to inspect the option descriptions and defaults. A recipe match uses the configured rule action, like any other match.

## Schema-4 example

The default rules file is `$XDG_CONFIG_HOME/imapledger/rules.toml`, or `~/.config/imapledger/rules.toml` when `XDG_CONFIG_HOME` is unset. A custom `--config PATH` uses the sibling `rules.toml`.

```toml
[rules]
schema = 4
default_match_at = 0.90

[rules.evidence]
trusted_authserv_ids = ["mx.example.org"]
trusted_provider_headers = ["X-Verified-Junk"]

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

[[rules.rule]]
id = "receipts"
enabled = true
type = "semantic"
action = "keep"
description = "Purchase receipts and order confirmations"
match_at = 0.93
```

Only add trusted evidence identifiers after verifying that the named receiver or provider inserts them. Authentication results and headers are otherwise untrusted message evidence. Source and destination mailbox names are exact and server-specific. imapledger does not create folders. MOVE requires server support; no COPY and EXPUNGE fallback is used.

## Manage and evaluate rules

```bash
imapledger rule list
imapledger rule show spam
imapledger rule add receipts --type semantic --action move \
  --destination INBOX.Receipts --description "Purchase receipts and order confirmations"
imapledger rule edit receipts --match from_domain=shop.example.org
imapledger rule move receipts up
imapledger rule test receipts --folder INBOX --uid 43724
imapledger rule evaluate --folder INBOX --uid 43724
imapledger rule learn receipts --folder INBOX --uid 43724 --preview
imapledger rule remove receipts
```

`rule add` creates a global rule unless `--source-folder` is supplied. Repeat `--match field=value` to add OR alternatives. `rule test` evaluates one rule; `rule evaluate` evaluates the ordered rule set. Both name one exact folder and UID and are read-only. Learning can add one safe deterministic matcher to an existing semantic rule after fit, safety, duplicate, conflict, and stale-fingerprint checks. It changes the rules file only and never moves the example message.

## Preview, apply, and deletion safety

```bash
imapledger rule preview INBOX --limit 10 --sort oldest
imapledger rule preview --all-folders --limit 10
imapledger rule apply INBOX --limit 10
imapledger rule apply --all-folders --limit 10
# Only when you intentionally configured a matching Delete action:
imapledger rule apply INBOX --allow-delete
```

Preview is read-only. Apply performs source and destination preflight and asks for confirmation unless `--yes` is supplied. A Delete action has a separate authorization gate: explicitly pass `--allow-delete`. `--yes` skips only the confirmation prompt and does not authorize deletion. Apply executes the plan for exact UIDs after checking the rules fingerprint, UIDVALIDITY, source membership, and configured action. A destination equal to the source is recorded as already there without a MOVE. Preflight is best-effort rather than transactional. Confirmed earlier actions are not rolled back if a later message fails; ambiguous MOVE results stop for reconciliation.

`--rule ID` limits evaluation to one enabled rule. `--new-run` supersedes active progress, and apply-only `--retry-errors` uses the matching run identity and scope. All-folder runs skip non-selectable folders and Config Ledger. `clean FOLDER` is a deprecated alias for preview/apply on one folder.

## Explicit migration

Schema-1, schema-2, and schema-3 rules files require explicit conversion:

```bash
imapledger rule migrate --preview
imapledger rule migrate --apply
```

The preview reports the source schema, converted rules, and warnings without writing. Schema-2 fallback destinations are dropped because unmatched mail now stays in place. Older Spam rule types become ordinary recipe rules. If migration would create any Delete rule, `--apply` also requires `--allow-delete`. Applying a rules-only migration writes schema 4 to `rules.toml`.

Legacy `[spam]` configuration is also migration-only. Normal configuration loading rejects it with guidance to run `rule migrate`. When an old Spam action is configured, migration can transfer its destination, source folders, thresholds, and trusted evidence to a regular Spam recipe rule. It does not create a Spam rule if no old Spam action was configured. Legacy `not_spam` and `review` actions are not migrated automatically; create separate rules if that behavior is still wanted. Review preview warnings carefully. If the migration includes a Delete action, the configuration migration also requires `--allow-delete` to apply. See [configuration](configuration.md) for details.

## TUI workbench

Run `imapledger ui` and press `R` to open the Rules workbench. An empty ruleset explains that no automatic actions are configured. The workbench supports searchable, category-filtered recipe discovery, rule scope and action editing, advanced recipe options, TOML preview, ordering, enable/disable, read-only tests, full-pipeline evaluation, explicit rules migration, and confirmed rule removal. Delete actions remain subject to separate authorization when applying. See [Interactive console](ui.md).
