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

`clean` is read-only unless `--apply` is supplied. The password is requested interactively and is never stored.

## Guides

```{toctree}
:maxdepth: 2

configuration
cleaning
rules
```

## Safety invariant

**Models judge content; deterministic code owns permissions and side effects.** Each IMAP session is bound to one source folder. Configured destinations are allow-listed and checked before actions. UIDs and UIDVALIDITY are checked before mutations. Separate source folders do not form a cross-folder transaction.
