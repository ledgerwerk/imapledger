# imapledger

`imapledger` is a security-scoped IMAP routing tool and an append-only ledger for small configuration files. The semantic model receives message evidence only; ordered rules and configured actions control every mail side effect.

## Quick start

```bash
imapledger folders --host imap.example.org --username me@example.org
imapledger init --host imap.example.org --username me@example.org
imapledger config show
imapledger rule recipe list
imapledger rule recipe add spam --id spam --destination INBOX.Junk
imapledger rule preview INBOX
imapledger rule apply INBOX
imapledger ui  # press R for the Rules workbench
imapledger progress list
```

`init` writes connection and authentication settings only. It creates no folders and adds no rules. Rules use schema 4 and are stored in `rules.toml` beside `config.toml`. No rules means no automatic mail actions. See the [configuration guide](configuration.md) and [rules guide](rules.md).

Credential resolution defaults to hidden prompt authentication, and no password is stored in configuration. Use `imapledger auth set` to opt into OS keyring or encrypted-vault storage; see the [configuration guide](configuration.md) for setup and credential handling.

## Guides

The configuration ledger stores readable snapshots in a dedicated existing IMAP folder. It is not a secret store. See the [configuration ledger guide](config-store.md) for bootstrap requirements and command workflows.

```{toctree}
:maxdepth: 2

configuration
config-store
cleaning
state
rules
ui
```

## Safety invariant

**Models judge content; deterministic code owns permissions and side effects.** Each IMAP session is bound to one source folder. Configured destinations are allow-listed and checked before actions. UIDs and UIDVALIDITY are checked before mutations. Delete requires explicit authorization. Separate source folders do not form a cross-folder transaction.
