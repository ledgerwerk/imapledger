# imapledger

A deliberately small, security-scoped IMAP automation tool. The MVP scans exactly one configured mailbox, asks `pyjev` whether each message is clearly spam, and can permanently delete only the exact UIDs that pass an application-owned threshold.

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
threshold = 0.95
max_message_bytes = 2000000
max_body_chars = 20000
```

There is deliberately no password setting.

`pyjev` authentication is separate; configure it as documented by `pyjev`.

## Dry run

```bash
imapledger clean
IMAP password:
```

Every invocation prompts for the IMAP password. The default run is read-only and reports `WOULD DELETE` rather than changing mail.

## Delete approved spam

```bash
imapledger clean --apply
IMAP password:
```

`--apply` refuses to run if the IMAP server does not advertise `UIDPLUS`. After classification, `imapledger` rechecks the mailbox `UIDVALIDITY`, verifies every approved UID still belongs to the same scoped mailbox, marks only those UIDs `\\Deleted`, and performs `UID EXPUNGE` only for those UIDs.

## Partial deletion results

Apply mode processes approved UIDs in ascending batches of at most 100. If a batch fails, `imapledger` attempts to clear `\\Deleted` from that failing batch and stops. Earlier `UID EXPUNGE` batches that succeeded remain deleted. The report marks only confirmed UIDs as `DELETED`, shows unresolved approved UIDs as `NOT CONFIRMED`, and exits with a failure status. Inspect the folder before retrying; an ambiguous server response is not treated as success.

## Troubleshooting and diagnostic privacy

Start with the read-only protocol probe:

```bash
imapledger doctor --verbose
```

`doctor` checks TLS, login, capabilities, the configured folder in read-only mode, UID search, one size fetch, and an eligible single-message `BODY.PEEK[]` probe. It does not run the classifier or change mail. Probe body bytes are discarded and never printed.

For a failing clean run, use `imapledger clean --verbose` to see safe operation progress, including size-fetch batch metadata. Add `--debug` for local traceback frames and exception class names. Neither option enables raw IMAP wire logging.

Errors identify the failed operation and include safe context such as the configured folder, selector, UID range, and batch. When the IMAP client exposes a recognized command rejection, diagnostics retain only its status token (`BAD`, `NO`, or `BYE`), not the raw server response. They do not print passwords, authentication payloads, exception messages, or message bytes. Verbose reports and message tables can still reveal folder names, account identifiers, UIDs, senders, and subjects; redact those details before sharing output.

For `FETCH` failures, note whether the operation is `imap_fetch_size` or `imap_fetch_body`. A size-fetch error includes its bounded batch number and UID range; a body-fetch error identifies one UID. `doctor --verbose` can determine whether the read path and one-message probes work independently of classification. If a destructive run reports pending UIDs, check the mailbox directly before retrying because their outcome was not confirmed.

## pyjev decision

`imapledger/decisions.toml` contains a named Noul decision named `spam`. `NoulResult.value` is treated as the probability of true. The application owns the threshold; the decision cannot perform side effects.

The message state sent to `pyjev` contains the UID, decoded subject/from/to/date fields, and a bounded plain-text body. Attachments are not sent in the MVP. Large messages are size-checked before their full body is fetched; oversized messages are reported as skipped and kept.

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
