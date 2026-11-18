# imapledger

A deliberately small, security-scoped IMAP automation tool. The MVP scans exactly one configured junk folder, asks `pyjev` to assess structured spam evidence, then applies an explicit application policy. Only a DELETE verdict can approve permanent removal of exact UIDs.

The semantic model never receives an IMAP client and cannot select folders or issue IMAP commands.

## Security model

The current cleaner has a narrow authority boundary:

- one IMAP account;
- one configured folder;
- TLS/IMAPS only in the MVP;
- no password storage;
- the password is requested with hidden `getpass()` input on every `clean` and `doctor` run;
- IMAP operations use explicit UID mode;
- the mailbox object drops its password reference immediately after the login attempt. This reduces reference lifetime but is not secure memory zeroization;
- dry-run is the default and selects the mailbox read-only;
- destructive mode requires `UIDPLUS`;
- deletion uses exact UID expunge, never ordinary mailbox-wide `EXPUNGE`;
- UIDs must belong to the initial mailbox snapshot;
- `UIDVALIDITY` is rechecked immediately before destructive operations;
- classifier errors and uncertain messages are kept.

This protects other folders from the application interface. It is not a server-side ACL: a process that has arbitrary code execution plus the IMAP password could still create its own unrestricted IMAP connection. A later version can add stronger credential isolation or a dedicated IMAP account with server-side ACLs.

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

```bash
imapledger init \
  --host imap.example.org \
  --username me@example.org \
  --folder Spam
```

The default file is `$XDG_CONFIG_HOME/imapledger/config.toml`, or `~/.config/imapledger/config.toml` when `XDG_CONFIG_HOME` is unset.

Example:

```toml
[imap]
host = "imap.example.org"
port = 993
username = "me@example.org"

[spam]
folder = "Spam"
max_message_bytes = 2000000
max_body_chars = 20000

[spam.policy]
legitimate_veto_at = 0.80
phishing_delete_at = 0.90
identity_deception_at = 0.90
unsolicited_bulk_at = 0.92
delete_safe_at = 0.88
provider_junk_support_at = 0.80

[spam.authentication]
trusted_authserv_ids = []

[spam.provider]
trusted_spam_headers = []
```



Legacy `spam.threshold` values are deprecated, warned about, and ignored. They are not mapped to the new named thresholds. The documented policy defaults apply when `[spam.policy]` is absent.
There is deliberately no password setting.

`pyjev` authentication is separate; configure it as documented by `pyjev`.

## Dry run

```bash
# Inspect the newest 10 messages (newest is the default sort)
imapledger clean --limit 10

# Inspect positions 11-20 among the newest messages
imapledger clean --limit 10 --offset 10 --sort newest

# Inspect the 25 oldest messages
imapledger clean --limit 25 --sort oldest
# Render the detailed report instead of streaming rows
imapledger clean --limit 10 --no-progress
```

Every invocation prompts for the IMAP password. The default run is read-only and reports `WOULD DELETE` for DELETE verdicts. REVIEW is a distinct non-destructive outcome and is kept. With no `--limit`, the selected window extends from `--offset` to the end of the initial mailbox snapshot.

`--sort newest` orders by descending IMAP UID, and `--sort oldest` orders by ascending IMAP UID. This is mailbox arrival order, not the message `Date:` header. `--offset` skips messages after sorting. The window is chosen from one stable initial UID snapshot, and only its selected UIDs are fetched for size metadata and eligible message bodies.

Progress is enabled by default. It streams one decision with its position and selected total as each message is classified. Use `--no-progress` to suppress per-message rows and render the detailed report at the end. `--verbose` is separate and adds safe IMAP protocol-operation diagnostics; it does not control classification progress.
## Apply DELETE verdicts

```bash
imapledger clean --apply
# Apply deletion only within the newest 10-message window
imapledger clean --apply --limit 10 --sort newest
IMAP password:
```

`--apply` refuses to run if the IMAP server does not advertise `UIDPLUS`. After classification, `imapledger` rechecks the mailbox `UIDVALIDITY`, verifies every approved UID still belongs to the same scoped mailbox, marks only those UIDs `\\Deleted`, and performs `UID EXPUNGE` only for those UIDs.


With progress enabled, apply-mode DELETE rows say `DELETE-APPROVED` while classification is pending. `DELETED` is reported only after the exact UID expunge succeeds. The summary distinguishes approved UIDs from confirmed deletions; partial deletion shows confirmed and pending UIDs and exits with a failure status.

## Partial deletion results

Apply mode processes approved UIDs in ascending batches of at most 100. If a batch fails, `imapledger` attempts to clear `\\Deleted` from that failing batch and stops. Earlier `UID EXPUNGE` batches that succeeded remain deleted. The report marks only confirmed UIDs as `DELETED`, shows unresolved approved UIDs as `NOT CONFIRMED`, and exits with a failure status. Inspect the folder before retrying; an ambiguous server response is not treated as success.

## Troubleshooting and diagnostic privacy

Start with the read-only protocol probe:

```bash
imapledger doctor --verbose
```

`doctor` checks TLS, login, capabilities, the configured folder in read-only mode, UID search, one size fetch, and an eligible single-message `BODY.PEEK[]` probe. It does not run the classifier or change mail. Probe body bytes are discarded and never printed.

For a failing clean run, use `imapledger clean --verbose` to see safe IMAP operation progress, including size-fetch batch metadata. Classification decisions stream by default; use `--no-progress` to disable those rows and `--debug` for local traceback frames and exception class names. Neither option enables raw IMAP wire logging.

Errors identify the failed operation and include safe context such as the configured folder, selector, UID range, and batch. When the IMAP client exposes a recognized command rejection, diagnostics retain only its status token (`BAD`, `NO`, or `BYE`), not the raw server response. They do not print passwords, authentication payloads, exception messages, or message bytes. Verbose output, streamed progress rows, and message tables can still reveal folder names, account identifiers, UIDs, senders, and subjects; redact those details before sharing output.

For `FETCH` failures, note whether the operation is `imap_fetch_size` or `imap_fetch_body`. A size-fetch error includes its bounded batch number and UID range; a body-fetch error identifies one UID. `doctor --verbose` can determine whether the read path and one-message probes work independently of classification. If a destructive run reports pending UIDs, check the mailbox directly before retrying because their outcome was not confirmed.

## Evidence bundle and policy

`imapledger/decisions.toml` defines one `spam-evidence` bundle with independent unsolicited-bulk, phishing/scam, identity-deception, legitimate/expected, and delete-safe questions. The classifier sends one structured state per message and validates every child probability. Operational UID data and raw authentication payloads are not sent as semantic evidence.

Local evidence extraction normalizes sender and reply identities, list/automation metadata, provider markers, Unicode display-name hints, and bounded URL hostnames. URL paths and query tokens are removed from model state and normal reports. Message-provided values are untrusted content, never instructions.

Authentication results remain untrusted unless an exact receiver `authserv-id` is explicitly configured under `[spam.authentication]`. Do not add guessed IDs. Generic spam headers remain soft evidence unless a trusted provider header is explicitly configured and the operator has verified that the provider inserts it. A passing SPF, DKIM, DMARC, or ARC result is identity evidence, not proof that a message is harmless.

The pure deterministic policy applies named thresholds. Strong legitimate/expected evidence vetoes deletion, phishing can qualify directly, and identity or unsolicited-bulk findings need corroboration. Provider and subject spam markers alone lead to REVIEW. Both REVIEW and KEEP are non-destructive; classifier, evidence, and policy errors fail closed.

The streamed row reports verdict, principal signals, and concise reasons. `--limit`, `--offset`, `--sort`, progress output, dry-run defaults, single-folder scope, UIDPLUS requirements, UIDVALIDITY checks, and exact-UID deletion remain unchanged. The small offline examples in `eval/spam_cases.jsonl` are synthetic and do not include real message bodies or recipient data.
## Tests

```bash
pytest
ruff check .
python -m build
python -m twine check dist/*
```

All tests are offline and use fake IMAP/classifier implementations.

## Roadmap

The package layout is intended to support additional workflows without turning the model into an unrestricted mail agent:

- **sort**: a source-scoped reader plus a deterministic allow-list of destination folders; the model proposes a route, Python validates and moves it;
- **daily digest**: read-only mailbox scopes, semantic importance scoring, then a local report/notification layer;
- **important mail alerts**: read-only polling/IDLE with explicit thresholds and deduplication;
- **credential hardening**: keyring, external secret helper, or a separate broker process so an agent never receives raw IMAP credentials;
- **server-side isolation**: dedicated IMAP account/ACLs where the provider supports them.

The invariant should remain: **models judge content; deterministic code owns permissions and side effects.**
