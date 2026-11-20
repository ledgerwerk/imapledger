# Cleaning and diagnostics

## Commands

```bash
imapledger clean
imapledger clean --limit 10
imapledger clean --limit 10 --offset 10 --sort newest
imapledger clean --apply
imapledger doctor
imapledger config show
```

`clean` is a dry run by default. It connects read-only to each configured source folder, classifies the selected messages, and reports planned actions such as `WOULD MOVE` or `WOULD DELETE`. It performs no mutations. Supply `--apply` to execute the actions configured for spam, not-spam, and review outcomes.

Credential-consuming commands resolve the configured source once per invocation. The default `prompt` source uses hidden input once, and the resolved password is reused across source folders. Keyring and vault sources retrieve stored credentials without prompting for the IMAP password.

## Source ordering and message selection

Configured source folders are opened sequentially in the order listed in `spam.folders`. Every source receives its own mailbox scope, initial UID snapshot, selection, and folder header. For example:

```text
folder=INBOX.Junk messages=36584 selected=10 sort=newest offset=0 limit=10
...
folder=INBOX.Spam messages=294 selected=10 sort=newest offset=0 limit=10
```

`--limit` and `--offset` apply independently to each configured source folder. For two folders, `--limit 10 --offset 10` selects positions 11 through 20 in each folder, for up to 20 classified messages total. `--sort newest` orders each folder by descending UID, and `--sort oldest` orders by ascending UID. These orders reflect mailbox-local arrival order, not the message `Date:` header. UIDs from different folders are not compared or merged into a global ordering.

`--progress` streams each classification and the final configured action for that message. `--no-progress` suppresses those rows and prints a final table with `Source`, `Outcome`, and `Action` columns. `--verbose` adds safe IMAP operation diagnostics. `--debug` prints local traceback frames and exception class names without raw exception payloads.

Every streamed result row includes `Folder=<exact configured source name>` immediately before the UID. This keeps source provenance visible on each row, including rule-match results.

## Outcome and action reporting

The current spam policy is unchanged. `SpamVerdict.DELETE` maps to the spam outcome, `SpamVerdict.KEEP` maps to not-spam, and `SpamVerdict.REVIEW` maps to review. Configuration determines the action for each outcome. A model, message body, or header cannot choose an action or destination.

Dry-run output can look like:

```text
[1/10] Folder=INBOX.Junk UID 43654  WOULD MOVE -> INBOX.Trash  Outcome=SPAM  Verdict=DELETE
[2/10] Folder=INBOX.Junk UID 43653  WOULD MOVE -> INBOX.NotSpam  Outcome=NOT_SPAM  Verdict=KEEP
[3/10] Folder=INBOX.Junk UID 43652  KEEP  Outcome=REVIEW  Verdict=REVIEW
```

## Persistent classification state

With `[spam.state].backend = "imap-keywords"`, `clean` skips previously marked messages before applying `--limit` and `--offset`. State is written only by `clean --apply` when the configured final action is `keep`; dry runs never write markers. Use `--reclassify` to ignore stored state for one run. Marker conflicts are not resolved automatically.

See [Persistent classification state](state.md) for the keyword support requirements, status and reset commands, read-only explanation behavior, review queue, and failure handling.

## Routing rule precedence

`clean` loads the separate `rules.toml` beside the selected config file. It checks the first enabled rule whose configured source folder and AND-combined matcher fields match the message before constructing a spam assessment. A match uses only the rule's `keep` or `move` action, bypasses spam classification for that message, and is reported as `Rule=<id>` without a spam verdict. Non-matching messages continue through the existing spam classifier and policy.

Rules apply only to source folders already listed in `spam.folders`; they cannot broaden the scan. A malformed rule file or out-of-scope source fails before mailbox processing. During dry-run, rule actions remain plans and no mailbox mutation occurs. With `clean --apply`, a rule move is applied to that exact UID immediately, before the next message is processed. Enabled rule move destinations are allow-listed and included in read-only preflight. Rule counts are reported separately from spam, not-spam, and review counts.

Use [`Learned routing rules`](rules.md) for the learning, storage, management, and read-only testing commands.

In apply mode, each configured MOVE or DELETE is attempted as its message is processed, before the progress callback and before the next message is classified. Progress reports the final action state after the attempt, using `MOVED` or `DELETED` only when confirmed:

```text
[1/10] Folder=INBOX.Junk UID 43654  MOVED -> INBOX.Trash  Outcome=SPAM  Verdict=DELETE
[2/10] Folder=INBOX.Junk UID 43653  MOVED -> INBOX.NotSpam  Outcome=NOT_SPAM  Verdict=KEEP
[3/10] Folder=INBOX.Junk UID 43652  KEEP  Outcome=REVIEW  Verdict=REVIEW
```

Dry-run remains read-only and continues to report `WOULD MOVE` or `WOULD DELETE`. Progress mode prints each action once, followed by the per-folder summary; `--no-progress` prints the final table instead.

Per-folder summaries contain semantic counts and action counts. A final aggregate summarizes totals across processed folders, while making clear that UIDs remain folder-scoped. Skipped messages and classification or policy errors always stay in their source folders. Review defaults to keep.

## Mutation safety and requirements

Before applying actions, imapledger checks the configured MOVE destination folders for the current source. Destinations must already exist. The program does not create folders, and MOVE is never replaced by COPY plus deletion.

`clean --apply` first runs a read-only preflight for every configured source. It checks authentication, required capabilities, exact source existence, read-only SELECT, and configured move destinations before classifier construction or action work. If any source fails, the command exits before any mutation. This is a best-effort preflight, not a transaction: mailbox state or capabilities can change afterward, so mutation-time checks and partial-result reporting still apply.

- A configured move action requires the IMAP MOVE capability.
- A configured delete action requires UIDPLUS.
- Dry-run does not require mutation capabilities.
- The writable source session captures UIDVALIDITY and the initial UID snapshot. Source-scoped reads and mutations reselect the exact configured folder before folder-local commands and verify UIDVALIDITY before using snapshot UIDs. Destination probes restore the source selection.
- A UIDVALIDITY change aborts the operation; imapledger never reuses old snapshot UIDs in a new generation. Streaming targets must belong to the initial snapshot and remain present in exact-UID `UID SEARCH` against the reselected source. Batch mutation validation also verifies source selection and live UID membership.
- Move destinations are checked against the configured allow-list. The classifier has no access to the IMAP client or destination names.
- Permanent deletion uses `\\Deleted` and exact-UID `UID EXPUNGE`, never mailbox-wide EXPUNGE.

## Partial failures

Each selected message's configured action is attempted in classification order. If a mutation fails or cannot be confirmed, the failing row is reported as not confirmed, no later message in that source is classified or mutated, and the command exits non-zero. Confirmed earlier actions are retained and are not rolled back. The report includes the operation error and any confirmed counts; inspect the pending message before retrying because an ambiguous IMAP response is not treated as success.

Source folders are separate operations, not one cross-folder transaction. If a later source folder fails to open, classify, or mutate, earlier confirmed changes are reported and are not rolled back. Processing stops at the failed folder. Inspect pending messages before retrying because an ambiguous IMAP response is not treated as success.

## Doctor

`imapledger doctor` is read-only and checks every configured source folder. It prompts once, then verifies the secure connection, login, read-only source selection, UID/search behavior, bounded size/body probes, action-related capabilities, and every configured move destination. It reports missing capabilities or destinations and exits non-zero. It does not classify messages, create folders, or mutate mail.

Missing configured sources are reported separately from sources that exist but cannot be selected. Source names are checked exactly as configured. Verify spelling and case against the server; imapledger does not create or substitute source folders.

Use `imapledger doctor --verbose` to print safe operation progress. Probe message bytes are discarded and never printed.

## Configuration reference

See [Configuration](configuration.md) for the TOML schema, supported actions, `config show`, and legacy `spam.folder` behavior.
