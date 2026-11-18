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

The password is requested once per `clean` or `doctor` invocation with hidden input. It is not stored. One classifier context is reused across all source folders in a `clean` invocation.

## Source ordering and message selection

Configured source folders are opened sequentially in the order listed in `spam.folders`. Every source receives its own mailbox scope, initial UID snapshot, selection, and folder header. For example:

```text
folder=INBOX.Junk messages=36584 selected=10 sort=newest offset=0 limit=10
...
folder=INBOX.Spam messages=294 selected=10 sort=newest offset=0 limit=10
```

`--limit` and `--offset` apply independently to each configured source folder. For two folders, `--limit 10 --offset 10` selects positions 11 through 20 in each folder, for up to 20 classified messages total. `--sort newest` orders each folder by descending UID, and `--sort oldest` orders by ascending UID. These orders reflect mailbox-local arrival order, not the message `Date:` header. UIDs from different folders are not compared or merged into a global ordering.

`--progress` streams each classification decision. `--no-progress` suppresses those rows and prints a final table with `Source`, `Outcome`, and `Action` columns. `--verbose` adds safe IMAP operation diagnostics. `--debug` prints local traceback frames and exception class names without raw exception payloads.

## Outcome and action reporting

The current spam policy is unchanged. `SpamVerdict.DELETE` maps to the spam outcome, `SpamVerdict.KEEP` maps to not-spam, and `SpamVerdict.REVIEW` maps to review. Configuration determines the action for each outcome. A model, message body, or header cannot choose an action or destination.

Dry-run output can look like:

```text
[1/10] UID 43654  WOULD MOVE -> INBOX.Trash  Outcome=SPAM  Verdict=DELETE
[2/10] UID 43653  WOULD MOVE -> INBOX.NotSpam  Outcome=NOT_SPAM  Verdict=KEEP
[3/10] UID 43652  KEEP  Outcome=REVIEW  Verdict=REVIEW
```

In apply mode, progress describes the approved action while classification is still running. It does not claim that a mutation has already happened:

```text
[1/10] UID 43654  MOVE-APPROVED -> INBOX.Trash  Outcome=SPAM  Verdict=DELETE
```

After classification completes for a source folder, configured action groups run in deterministic order: spam, not-spam, then review. Final reporting uses `MOVED` or `DELETED` only for confirmed actions. Pending or ambiguous operations are reported as not confirmed.

Per-folder summaries contain semantic counts and action counts. A final aggregate summarizes totals across processed folders, while making clear that UIDs remain folder-scoped. Skipped messages and classification or policy errors always stay in their source folders. Review defaults to keep.

## Mutation safety and requirements

Before applying actions, imapledger checks the configured MOVE destination folders for the current source. Destinations must already exist. The program does not create folders, and MOVE is never replaced by COPY plus deletion.

- A configured move action requires the IMAP MOVE capability.
- A configured delete action requires UIDPLUS.
- Dry-run does not require mutation capabilities.
- The source mailbox is reselected before mutation. UIDVALIDITY is checked again, and each requested UID must belong to the initial source snapshot and still exist in that source.
- Move destinations are checked against the configured allow-list. The classifier has no access to the IMAP client or destination names.
- Permanent deletion uses `\\Deleted` and exact-UID `UID EXPUNGE`, never mailbox-wide EXPUNGE.

## Partial failures

Actions are batched. If a batch fails, imapledger stops later action groups for that source folder. Confirmed earlier batches remain applied. UIDs in the failed and later batches are pending, not confirmed. The command exits non-zero and reports the source, destination when relevant, batch metadata, safe server status, and confirmed counts.

Source folders are separate operations, not one cross-folder transaction. If a later source folder fails to open, classify, or mutate, earlier confirmed changes are reported and are not rolled back. Processing stops at the failed folder. Inspect pending messages before retrying because an ambiguous IMAP response is not treated as success.

## Doctor

`imapledger doctor` is read-only and checks every configured source folder. It prompts once, then verifies the secure connection, login, read-only source selection, UID/search behavior, bounded size/body probes, action-related capabilities, and every configured move destination. It reports missing capabilities or destinations and exits non-zero. It does not classify messages, create folders, or mutate mail.

Use `imapledger doctor --verbose` to print safe operation progress. Probe message bytes are discarded and never printed.

## Configuration reference

See [Configuration](configuration.md) for the TOML schema, supported actions, `config show`, and legacy `spam.folder` behavior.
