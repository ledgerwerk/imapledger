# Routing state and progress

The unified rules workflow stores resumable run progress in a local SQLite database. It does not use IMAP keywords for Spam, not-Spam, or review state. The former classification-state, review-queue, and per-message `explain` workflows have been removed. Existing mailbox keywords are not used or removed by rule migration.

## Progress database

The default database is `$XDG_STATE_HOME/imapledger/progress.sqlite3`, or `~/.local/state/imapledger/progress.sqlite3` when `XDG_STATE_HOME` is unset. Set `--progress-db PATH` on rule-run and progress commands to use another file.

```bash
imapledger progress list
imapledger progress show INBOX
imapledger progress errors INBOX
imapledger rule apply INBOX --retry-errors
imapledger rule preview INBOX --new-run
imapledger progress reset INBOX
```

Progress records identify the account with a hash and track source folder, UIDVALIDITY, fixed UID bounds, rules fingerprint, run mode, rule scope, sort direction, counters, and per-UID outcomes or safe error codes. They do not store the IMAP password or message bodies.

A run can resume only when its account, folder, UIDVALIDITY, rules fingerprint, mode, rule scope, and sort direction match. Changing a rule or scope cannot silently reuse an incompatible cursor. `--new-run` explicitly supersedes active progress. `--retry-errors` is apply-only and uses the matching run identity and scope. UIDVALIDITY changes invalidate existing progress; inspect the mailbox before starting another run.

Recorded outcomes distinguish matches and no-matches from actions such as `kept`, `moved`, `deleted`, `already_there`, `blocked`, and errors. Preview does not change mailbox messages. Apply checkpoints safe results as processing proceeds. New UIDs arriving after a run starts do not extend that run's fixed high-watermark.

## Reset saved progress

`progress reset FOLDER` deletes saved local runs for that source folder after confirmation. It does not connect to IMAP or change messages, flags, or keywords. The reset cannot be undone. Use `--progress-db PATH` to target a non-default database.

There is no `state reset` command for classification keywords. If old `imapledger-v1-*` keywords remain in a mailbox, they are inert application data for the current rule runner. Configuration migration does not edit or delete them.

## Failure and privacy behavior

Ordinary per-UID failures are recorded and scanning may continue. An unconfirmed or ambiguous MOVE stops the run for reconciliation. Confirmed earlier actions are not rolled back. Processing across folders is not one transaction. Progress output contains operational metadata and safe error codes; it can still reveal folder names, UIDs, and account context, so review it before sharing.

See [Rule preview, apply, and progress](cleaning.md) for run limits, exact-message safeguards, and apply behavior.
