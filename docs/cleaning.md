# Cleaning and diagnostics

`clean FOLDER` runs the resumable routing pipeline on one exact source mailbox. The `spam.folders` field is optional for this path, although the application configuration must still contain IMAP and spam-policy settings. Preview is the default; only `--apply` moves messages.

## Resumable routing

```bash
imapledger clean INBOX.Junk
imapledger clean INBOX.Junk --limit 10
imapledger clean INBOX.Junk --limit 10 --apply
imapledger clean INBOX.Junk --rule newsletter --limit 10 --apply
imapledger clean INBOX.Junk --sort newest --apply
```

A full run evaluates all enabled applicable rules in priority order. The first match selects its configured destination; if none matches, the fallback destination is used. Full mode requires `rules.fallback_destination`. `--rule ID` evaluates only that enabled rule. A non-match in single-rule mode stays in the source and is still scanned and checkpointed by an applied run. See [Unified routing rules](rules.md) for rule types and configuration.

The default sort for positional `clean FOLDER` is oldest-first. `--sort newest` reverses UID order. `--limit` bounds the number of messages processed by this invocation. `--offset` is available only in legacy compatibility mode. Scanning uses bounded UID windows and batched fetches; it does not fetch a full-mailbox UID snapshot for a small limit.

Every run records a fixed UID high-watermark and lower boundary. New UIDs arriving after the run begins do not extend it. A completed run's next normal run starts after its previous high-watermark, so it handles newly arrived UIDs rather than rescanning the completed range. `--new-run` supersedes active progress and starts a fresh scan. An active run resumes only when account identity, source folder, UIDVALIDITY, rule fingerprint, full or single-rule mode, rule scope, and sort direction match. A rule or sort change cannot silently continue a prior cursor.

Preview evaluates messages but never advances the durable UID cursor or stores per-message checkpoints. It can be repeated safely. Apply records per-message results and checkpoints transactionally as processing proceeds. A successful full-pipeline move is confirmed for the exact UID before the checkpoint advances. Source UIDs and UIDVALIDITY are revalidated before mutation.

## Progress and retry

The local SQLite progress database defaults to `$XDG_STATE_HOME/imapledger/progress.sqlite3`, or `~/.local/state/imapledger/progress.sqlite3` when `XDG_STATE_HOME` is unset. Override it with `--progress-db PATH`. Account identity is hashed; progress records contain routing metadata and safe error codes, not credentials or message bodies.

```bash
imapledger progress list
imapledger progress show INBOX.Junk
imapledger progress errors INBOX.Junk
imapledger progress reset INBOX.Junk
```

`list` shows runs for the configured account. `show` reports the latest run for a source. `errors` lists retryable error codes, not message contents. `reset` deletes saved runs for one source after confirmation. UIDVALIDITY changes invalidate old runs; reconcile the mailbox before starting a new run rather than reusing old UIDs.

Ordinary per-UID processing errors are recorded and scanning continues, so other messages can be completed. Retry those errors only with apply and the matching rules and scope:

```bash
imapledger clean INBOX.Junk --retry-errors --apply
```

Retry uses the matching run's UIDVALIDITY, rule fingerprint, mode, scope, and sort direction. It cannot be combined with `--new-run`. If an IMAP MOVE result is ambiguous or unconfirmed, processing stops instead of guessing whether the message moved. Inspect the mailbox and progress record before retrying.

Progress output is on by default and reports each UID evaluation, planned or confirmed destination, and final counters. `--no-progress` suppresses per-message rows. `--verbose` prints safe IMAP operation progress. `--debug` prints local traceback frames and exception class names without exception payloads.

## Legacy bare-clean compatibility

For one compatibility period, omitting the source folder retains the older classifier workflow over `spam.folders`:

```bash
imapledger clean
imapledger clean --limit 10 --offset 10 --sort newest
imapledger clean --apply
```

Bare `clean` emits a deprecation warning. This path uses the configured SPAM, NOT_SPAM, and REVIEW actions, supports `--offset` and the legacy classification-state keywords, and uses newest-first by default. It does not use resumable routing progress. Migrate scripts to `clean FOLDER` and schema-2 rules. `spam.folders` remains the source list for bare-clean compatibility and for older classification commands, not a boundary on the positional pipeline.

## Mutation safety

`--apply` checks the exact source and every enabled rule and fallback destination read-only before processing. Destinations must already exist. The pipeline uses IMAP MOVE on exact UIDs; it does not create folders or fall back to COPY plus EXPUNGE. Each mailbox session is bound to one source folder. UIDVALIDITY and live UID membership are checked before mutation, and a routing plan is validated against the active rule order and fingerprint before MOVE.

Preflight is best-effort, not a transaction. Mailbox state or server capabilities can change afterward. Confirmed earlier moves remain applied when later messages fail; there is no rollback. An ambiguous move stops the run. Separate source-folder runs are not one cross-folder transaction.

## Doctor

`imapledger doctor` is read-only and checks the configured compatibility source folders, mailbox selection, UID/search behavior, bounded fetches, required capabilities, destinations, and optional config-store folder. It does not classify messages, create folders, or mutate mail. Use `imapledger doctor --verbose` for safe operation progress.

## Troubleshooting and privacy

Use `--verbose` to see safe IMAP operation progress. Use `--debug` for local traceback frames and exception class names. Diagnostics do not include passwords, authentication payloads, message bytes, exception messages, or raw server responses. They may still reveal folder names, account identifiers, UIDs, senders, or subjects; redact before sharing.

See [Persistent state](state.md) for legacy IMAP classification keywords, and [Configuration](configuration.md) for the application TOML schema.
