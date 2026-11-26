# Configuration ledger

imapledger can keep small, human-readable configuration files for arbitrary tools in a dedicated IMAP folder. Each push appends an immutable snapshot message. This ledger is separate from spam classification and does not change `imapledger config show`, which continues to display the effective local imapledger application configuration without prompting or connecting to IMAP.

> **Security warning:** Configuration snapshots are stored as readable email. Do not use the configuration ledger as a password, token, private-key, or secret store. Mailbox access, provider retention, and account compromise can expose every stored snapshot.

## Bootstrap and setup

The config-ledger commands need only the local IMAP connection settings and a configured store folder. They do not require a `[spam]` section. Keep the information needed to discover and authenticate to IMAP locally:

- IMAP host, port, and username;
- credential source under `[imap.auth]`;
- the config-store folder name.

The IMAP password continues to come from the existing prompt, keyring, or VaultConfig credential flow. It is resolved once per command and is never stored in a snapshot.

Add an optional section to the local imapledger configuration:

```toml
[imap]
host = "imap.example.org"
port = 993
username = "me@example.org"

[imap.auth]
source = "prompt"

[config_store]
folder = "INBOX.imapledger.Config"
max_file_bytes = 1048576
```

The folder must already exist and be selectable. `push` never creates it. `max_file_bytes` defaults to 1 MiB and cannot exceed 10 MiB. `imapledger doctor` checks the configured store folder read-only. The folder is reserved application data and cannot also be a configured cleaning source or move destination.

Storing `imapledger`'s own local configuration is supported, but a completely empty machine cannot discover its IMAP account from the remote ledger. The local bootstrap settings and a working credential source must be available first. Credential vault files are not uploaded automatically and should not be pushed manually.

## When the optional store is disabled

`[config_store]` is optional. Without it, `imapledger config list` does not attempt an IMAP connection and exits successfully with `Config store: disabled` plus guidance to add the table. Remote operations such as `push`, `versions`, `diff`, `pull`, and `cat` still fail with a non-zero exit and an actionable configuration error. `imapledger config show` remains a local-only command and does not require the store.

## Snapshot contents and history

A snapshot is a MIME email with machine-readable `X-Imapledger-*` metadata, a readable text representation, and an authoritative attachment containing the exact UTF-8 file bytes. The attachment is verified against the declared size and SHA-256 before content is returned. Snapshot identity and current state come from stable version IDs and parent links, not from mutable IMAP flags, message dates, or UID ordering.

A normal push adds a new child of the current history head. Existing messages are not edited or removed. If the bytes, stored default path, and filename are unchanged from the current version, push reports that the version is already current and appends nothing. Concurrent branches are reported as a conflict rather than choosing a winner based on date or UID. Resolve a conflict explicitly by pushing the chosen local file with `--resolve-conflict`; the new snapshot records every current head as a parent.

`config list` and `config versions TOOL` discover snapshots and read metadata without fetching configuration bodies. A corrupt or malformed snapshot is reported rather than silently becoming current. `--verbose` shows corruption details for `list`, and transport metadata including UID, UIDVALIDITY, Message-ID, parent IDs, and the full content hash for `versions`.

## Commands

Push a local UTF-8 text file under a logical tool name:

```bash
imapledger config push ruff ~/.config/ruff/ruff.toml
imapledger config push pyjev ~/.config/pyjev/config.toml
```

Tool names are normalized to lowercase. The source path is recorded as metadata, not included in the file content. Paths inside the current home directory are stored portably using `~`; paths outside the home directory remain absolute.

Inspect stored tools and one tool's versions:

```bash
imapledger config list
imapledger config versions ruff
imapledger config versions ruff --verbose
```

Read a selected snapshot without writing a file:

```bash
imapledger config cat ruff
imapledger config cat ruff --version VERSION_ID
```

`cat` writes only the exact stored UTF-8 text to stdout. Diagnostics are written to stderr.

Compare local and stored content. Direction is required and controls the `---` and `+++` sides of the unified diff:

```bash
imapledger config diff ruff --direction local-to-imap
imapledger config diff ruff --direction imap-to-local
imapledger config diff ruff --path ./candidate.toml --direction local-to-imap
imapledger config diff ruff --version VERSION_ID --direction local-to-imap
```

By default, diff uses the selected snapshot's stored path as the local file. Exit status is `0` for no differences, `1` when differences are found, and `2` for usage, configuration, IMAP, or integrity errors.

Pull a current or explicit version:

```bash
imapledger config pull ruff
imapledger config pull ruff --to /tmp/ruff.toml
imapledger config pull ruff --version VERSION_ID
```

A missing target is created atomically. An identical target is left untouched. A differing existing target is shown as a unified diff and requires confirmation before replacement. Answering no leaves the file unchanged. `--force` skips the prompt and automatic diff; `--force --show-diff` still prints the diff before reporting the write. `--to` always overrides the recorded default path.

For a stored default path outside the current user's home directory, pull requires an explicit `--to` destination. This prevents remote metadata from silently choosing an arbitrary system path.

## Secret handling and limits

Before push, imapledger scans text for likely secret fields such as passwords, API keys, bearer authorization values, and private-key markers. It reports field names and line numbers, never the detected values. This scan is best-effort, not a guarantee, and cannot establish that a file is safe to store. Review every file before pushing it.

When a finding is intentional, acknowledge the plaintext exposure explicitly:

```bash
imapledger config push my-tool config.toml --allow-sensitive-plaintext
```

This acknowledgement is separate from `--force`, which applies only to pull overwrite behavior. Snapshots are not encrypted by imapledger and are readable to clients with access to the configured mailbox.

V1 supports individual UTF-8 text files only. It does not normalize configuration syntax or line endings. Directories, bundles, binary files, transparent encryption, remote editing, automatic synchronization, and automatic conflict merging are out of scope.

## Retention and backup

The ledger has no automatic retention, pruning, or version deletion. Pushes append; they do not delete earlier snapshots. IMAP is not an immutable backup medium: mailbox owners, administrators, or provider retention and deletion policies may remove messages and break parent history. Use an independent backup if these configurations must be recoverable. Future deletion tools must be explicit and account for parent links before removing history.
