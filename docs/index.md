# imapledger

`imapledger` is a security-scoped IMAP tool for classifying messages and an append-only ledger for small configuration files. The semantic model receives message evidence only; deterministic policy and configuration control every cleaning side effect.

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

The configuration ledger stores readable snapshots in a dedicated existing IMAP folder. It is not a secret store and does not require spam settings. See the [configuration ledger guide](config-store.md) for bootstrap requirements and command workflows.

```{toctree}
:maxdepth: 2

configuration
config-store
cleaning
state
rules
```

## Safety invariant

**Models judge content; deterministic code owns permissions and side effects.** Each IMAP session is bound to one source folder. Configured destinations are allow-listed and checked before actions. UIDs and UIDVALIDITY are checked before mutations. Separate source folders do not form a cross-folder transaction.
