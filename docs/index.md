# imapledger

`imapledger` is a security-scoped IMAP tool for classifying messages and applying configured, deterministic mailbox actions. It supports multiple source folders, dry-run by default, and explicit MOVE or delete actions. The semantic model receives message evidence only. Python policy and configuration control every side effect.

## Quick start

```bash
imapledger folders --host imap.example.org --username me@example.org
imapledger init \
  --host imap.example.org \
  --username me@example.org \
  --folder INBOX.Junk \
  --folder INBOX.Spam \
  --spam-action move \
  --spam-destination INBOX.Trash \
  --not-spam-action move \
  --not-spam-destination INBOX.NotSpam

imapledger config show
imapledger doctor
imapledger clean
imapledger clean --apply
```

Credential resolution defaults to hidden prompt authentication, and no password is stored in configuration. Use `imapledger auth set` to opt into OS keyring or encrypted-vault storage; see the configuration guide for setup and deletion behavior.

## Guides

```{toctree}
:maxdepth: 2

configuration
cleaning
state
rules
```

## Safety invariant

**Models judge content; deterministic code owns permissions and side effects.** Each IMAP session is bound to one source folder. Configured destinations are allow-listed and checked before actions. UIDs and UIDVALIDITY are checked before mutations. Separate source folders do not form a cross-folder transaction.
