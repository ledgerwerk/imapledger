# Rule preview, apply, and progress

The schema-4 rule runner previews or applies ordered rules to selected mail folders. Preview is read-only. Apply is explicit, confirmation-gated by default, and uses exact UIDs after preflight. No-match and `keep` leave mail in place; a destination equal to the source is reported as already there without MOVE.

## Select a folder scope

```bash
imapledger rule preview INBOX.Junk --limit 10
imapledger rule preview INBOX.Junk --rule newsletters --sort newest
imapledger rule preview --all-folders --limit 10

imapledger rule apply INBOX.Junk --limit 10
imapledger rule apply INBOX.Junk --rule newsletters --yes
imapledger rule apply --all-folders --limit 10
```

Use exactly one folder or `--all-folders`. All-folder runs skip non-selectable folders and Config Ledger. `--limit` bounds work per folder, and `--sort` chooses oldest-first or newest-first mailbox-local UID order. `--rule ID` evaluates only the selected enabled rule. Apply asks for confirmation unless `--yes` is supplied. The deprecated `clean FOLDER` command is an alias for a one-folder preview or apply.

Delete is an ordinary rule action but has a separate safety gate. An apply that may execute a Delete action must include `--allow-delete`. `--yes` skips only the confirmation prompt and does not authorize deletion. The TUI also requires explicit delete authorization.

## Progress and retry

The local SQLite progress database defaults to `$XDG_STATE_HOME/imapledger/progress.sqlite3`, or `~/.local/state/imapledger/progress.sqlite3` when `XDG_STATE_HOME` is unset. Override it with `--progress-db PATH`. Account identity is hashed; progress records contain routing metadata and safe error codes, not credentials or message bodies.

```bash
imapledger progress list
imapledger progress show INBOX.Junk
imapledger progress errors INBOX.Junk
imapledger progress reset INBOX.Junk
imapledger rule apply INBOX.Junk --retry-errors
imapledger rule preview INBOX.Junk --new-run
```

A run is identified by account, source folder, UIDVALIDITY, rules fingerprint, mode, rule scope, and ordering. A changed rule or scope cannot silently resume an old cursor. `--new-run` supersedes active progress. `--retry-errors` is apply-only and uses the matching run identity and scope.

Apply checkpoints safe outcomes as processing proceeds. New UIDs arriving after a run starts do not extend its fixed high-watermark. UIDVALIDITY changes invalidate existing progress. Ordinary per-UID errors are recorded and scanning can continue. An unconfirmed or ambiguous MOVE stops for reconciliation. Confirmed earlier actions are not rolled back. Separate folders are not one cross-folder transaction.

## Mutation safety

Apply checks the source and configured MOVE destinations read-only before processing. Destinations must already exist, cannot be the source or Config Ledger, and must support IMAP MOVE. Each mailbox session is bound to one source folder. Before mutation, imapledger validates the current rules fingerprint, UIDVALIDITY, live UID membership, and exact configured action. It never creates folders or falls back to COPY and EXPUNGE. Delete uses the exact-message deletion path and requires explicit authorization.

Preflight is best-effort, not a transaction. Server capabilities or mailbox state can change afterward. Ambiguous moves stop instead of guessing whether mail moved. Use `--verbose` for safe IMAP operation progress. `--debug` prints local traceback frames and exception class names without exception payloads.

See [Unified routing rules](rules.md) for schema, migration, matching, and no-match behavior, and [Routing state and progress](state.md) for the local progress database.
