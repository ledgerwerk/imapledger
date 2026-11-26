# Persistent classification state

imapledger can store a coarse classification outcome on each message as an IMAP keyword. The keyword lives in the recipient's mailbox, not in the message headers, so a sender cannot supply or forge imapledger state by adding a header.

## Configuration and server support

The state backend is configured under `[spam.state]`:

```toml
[spam.state]
backend = "imap-keywords"
```

Supported values are:

| Backend         | Behavior                                                                                                                            |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `none`          | Do not persist classification state. This is the default for existing configurations that omit `[spam.state]`.                      |
| `imap-keywords` | Use the application-owned IMAP keywords described below. Newly generated configurations from `imapledger init` select this backend. |

`imapledger config show` displays the effective backend. Keyword names and the marker version are application-owned, not user configuration.

The selected source mailbox must advertise persistent custom keywords in `PERMANENTFLAGS`: either `\\*` or the exact keyword must be listed. A successful IMAP `STORE` response alone is not sufficient. imapledger verifies keyword state after writes. `doctor` reports support as `OK`, `UNSUPPORTED`, or `UNKNOWN` when a read-only probe cannot determine it.

In deprecated bare-clean compatibility mode, when `imap-keywords` is enabled and an applied run can keep an outcome, preflight checks keyword persistence before classification. Unsupported persistence fails closed before classifier work. If persistence fails during processing, that message is not reported as successfully persisted, the run stops, and later messages are not processed. Preflight is best-effort and does not make mailbox operations transactional. Positional `clean FOLDER` uses the separate local progress database described below.

## Markers and versioning

The v1 markers identify only the coarse outcome:

| IMAP keyword            | Outcome  |
| ----------------------- | -------- |
| `imapledger-v1-spam`    | Spam     |
| `imapledger-v1-notspam` | Not-spam |
| `imapledger-v1-review`  | Review   |

The `v1` component is a marker schema epoch. It is not the imapledger package version or the pyjev model version. Do not rename or manually add these markers. A future incompatible marker format should use an explicit migration rather than silently changing the meaning of v1.

The markers do not store confidence, model or request IDs, policy reasons, timestamps, hashes, message content, or audit history. Only outcomes that finish with a configured `keep` action are persisted, and only when bare `clean --apply` uses the legacy classification workflow. Move and delete actions do not need a source marker. Dry runs never write state.

With the keyword backend enabled, bare `clean` excludes messages carrying any imapledger state marker before applying `--offset` and `--limit`. This avoids repeatedly classifying marked messages and ensures selection bounds apply to unclassified messages. Positional `clean FOLDER` does not consult these markers. Conflicting markers are not resolved by guessing; `state status` counts conflicts and `explain` reports a state error for the affected UID.

Use bare `clean --reclassify` to ignore existing classification state for that compatibility run. A reclassification is still read-only without `--apply`. If an applied reclassification ends in `keep`, imapledger replaces the old outcome marker with the current outcome and verifies the result.

## Inspect state

```bash
imapledger state status
```

This command is read-only and does not fetch message bodies. For each configured source it reports the exact folder name, UIDVALIDITY, backend, keyword persistence support, total message count, counts for each marker, unclassified count, and conflicting-state count. It uses IMAP keyword searches rather than scanning message contents.

## Reset state

`state reset` is a mutation and is a dry run unless `--apply` is provided. It removes only the three application-owned v1 classification keywords. Other IMAP flags and keywords are left unchanged.

Reset one exact UID in one configured source:

```bash
imapledger state reset --folder INBOX.Junk --uid 43652
imapledger state reset --folder INBOX.Junk --uid 43652 --apply
```

Reset all marked UIDs in one configured source, or all configured sources:

```bash
imapledger state reset --folder INBOX.Junk --all --apply
imapledger state reset --all-folders --all --apply
```

An unbounded reset requires `--all`. `--all-folders` must be combined with `--all` and cannot be combined with `--folder`. A selected folder must be configured as a source. An exact UID must belong to that folder's initial UID snapshot; otherwise the reset is refused. Every keyword removal is verified, and the final state is checked for remaining application markers. A partial IMAP failure exits non-zero; reset is not a cross-folder transaction.

Reset is the explicit invalidation mechanism when you want marked messages to be eligible for classification again after changing policy or model behavior.

## Explain one message

```bash
imapledger explain 43652 --folder INBOX.Junk
imapledger explain 43652 --folder INBOX.Junk --reclassify
```

`explain` is read-only and requires a configured source folder and an exact UID in the initial mailbox snapshot. It reports the persisted outcome, message headers, normalized sender information, and the configured action for that outcome. The action shown is the current configuration, not a historical record of the action previously taken.

For a message with stored state, the default command uses a header-only fetch and skips the classifier. Authentication and provider-spam evidence are not stored in the marker, so this mode reports them as not fetched. `--reclassify` runs the current deterministic rules and classifier even if state exists. When there is no stored outcome, `explain` also evaluates the current rules and classification by default. Those paths fetch the message using `BODY.PEEK[]`; they do not mark it as read or print its body. A matching deterministic rule is reported with its configured action and bypasses spam classification.

When classification runs, the output includes semantic signal values, the policy verdict and reasons, and the configured final action. Authentication evidence is identified as trusted only when its receiver `authserv-id` is configured. Provider-spam evidence is identified as trusted only for explicitly configured provider headers. Untrusted evidence remains message-provided data and is not treated as authoritative state.

## Review queue

`review list` lists messages carrying the review marker. It never constructs pyjev and fetches only `From`, `Subject`, `Date`, and `Message-ID` headers, not message bodies.

```bash
imapledger review list
imapledger review list --folder INBOX.Junk --limit 20
imapledger review list --folder INBOX.Junk --limit 20 --offset 20 --sort oldest
```

Without `--folder`, each configured source is inspected. `--limit`, `--offset`, and `--sort` apply independently per source; `newest` sorts by descending mailbox-local UID and `oldest` by ascending UID. The folder must be a configured source.

## Privacy and failure behavior

IMAP keywords do not alter message headers or body. State status and review listing do not fetch message bodies. Cached-state `explain` also uses headers only. `explain --reclassify` and explanation of an unmarked message use the ordinary classifier path, read the message with `BODY.PEEK[]`, and do not mutate the mailbox. Avoid sharing diagnostic output without reviewing it: it can contain folder names, UIDs, sender addresses, subjects, and message IDs.

## Resumable routing progress

The positional `clean FOLDER` pipeline uses a separate local SQLite database, not IMAP keywords. It defaults to `$XDG_STATE_HOME/imapledger/progress.sqlite3`, or `~/.local/state/imapledger/progress.sqlite3` when `XDG_STATE_HOME` is unset; `--progress-db PATH` selects another file. Progress records identify the IMAP account with a hash and store the source folder, UIDVALIDITY, fixed run UID bounds, rules fingerprint, mode, scope, sort direction, counters, and safe per-UID outcome/error codes. They do not store passwords or message bodies.

```bash
imapledger progress list
imapledger progress show INBOX.Junk
imapledger progress errors INBOX.Junk
imapledger progress reset INBOX.Junk
```

Preview does not advance the durable cursor. Apply checkpoints completed results transactionally. Runs resume only when their account, folder, UIDVALIDITY, rules, mode, scope, and sort direction match. UIDVALIDITY changes invalidate a run; reconcile before starting a new scan. `progress reset` deletes saved runs for one folder after confirmation. It is separate from `state reset`, which removes only legacy classification keywords from IMAP.
All state writes and resets are scoped to a configured source folder and UIDs from its initial snapshot. Unsupported persistence, state conflicts, vanished UIDs, or unverifiable writes fail closed. `state reset` is the supported way to clear application state; manually editing unrelated system flags is unnecessary and can change mailbox behavior.
