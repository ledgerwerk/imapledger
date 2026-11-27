# Interactive mail and rule workbench

Launch the terminal interface with:

```bash
imapledger ui
```

The TUI is the interactive frontend for mailbox browsing, unified rules, progress, diagnostics, credentials, configuration, and Config Ledger. It shares application operations with the CLI and does not shell out to CLI subprocesses. Startup is disconnected and does not resolve credentials. Opening a message uses read-only `BODY.PEEK`; it does not mark mail seen, fetch remote images, render HTML, or open attachments.

## Keyboard shortcuts

| Key                    | Action                                                            |
| ---------------------- | ----------------------------------------------------------------- |
| Left / `H`             | Focus the previous pane                                           |
| Right / `L`            | Focus the next pane                                               |
| Tab / Shift+Tab        | Cycle focus through panes                                         |
| Up / Down or `k` / `j` | Move through folders or messages; scroll detail                   |
| Home / End             | Move to the first or last item or top or bottom of detail         |
| PageUp / PageDown      | Page through the focused pane                                     |
| `x`                    | Preview rules on 10 messages in the selected folder               |
| `X`                    | Open multi-folder rule preview/apply options                      |
| `c`                    | Evaluate rules for the selected message                           |
| `e`                    | Explain the current evaluation without rerunning it               |
| `l`                    | Learn a matcher for an existing semantic rule                     |
| `a`                    | Apply the displayed MOVE or authorized DELETE plan after confirmation |
| `R`                    | Open the unified Rules workbench                                  |
| `p` / `d`              | Inspect routing progress / open system diagnostics             |
| `s`                    | Open System for setup, connection, credentials, and config        |
| `:`                    | Open Command Center and search available operations               |
| `G`                    | Open Config Ledger                                                |
| `i` / `I`              | Analyze embedded images / review remote images after confirmation |
| `r`                    | Refresh                                                           |
| `h` / `?`              | Open keyboard help                                                |
| `q`                    | Quit                                                              |

The focused pane has a highlighted border. Pane navigation follows the widget currently holding focus, including focus reached with the mouse.

## Rule preview and apply

`x` previews the next 10 messages in the selected real folder. Preview is read-only. `X` opens rule-run options for selecting one or more folders or all selectable folders, setting a limit and ordering, and choosing preview or apply. Config Ledger and non-selectable folders are excluded. Apply performs read-only preflight before explicit confirmation and shows whether Delete actions are authorized. The job screen streams safe results and supports cooperative cancellation.

Batch work uses the same rule-run operation as the CLI. Apply rechecks source and MOVE destinations, current rules, UIDVALIDITY, exact UIDs, and progress identity before executing actions. No-match and KEEP leave messages in place. A message already in its destination is reported as already there without MOVE.

## Evaluate and explain one message

Press `c` with a message selected to evaluate the ordered rules. The analysis panel shows rule results, semantic confidence where available, the first matching rule, action, destination when applicable, and whether the result is MOVE, KEEP IN PLACE, DELETE, or ALREADY THERE. Evaluation is read-only.

Press `e` to explain the existing evaluation. It does not send a second model request or reevaluate. If no evaluation exists yet, the screen tells you to press `c`. Press `a` to confirm the current MOVE or authorized Delete plan. The confirmation names the source folder, exact UID, winning rule, and action, and is bound to the plan shown when it opened. Stale rules, UIDVALIDITY, or message identity fail closed.

## Rules workbench and learning

Press `R` to open the schema-4 Rules workbench. Rules are global by default, and an empty workbench clearly states that no automatic actions are configured. Browse the shared recipe catalog with search and category filters, then edit the rule ID, type, scope, action, destination, and advanced recipe options. Preview the resulting TOML before saving. The workbench also supports priority changes, enable/disable, read-only tests, full-pipeline evaluation, explicit migration of older rule files, and confirmed rule removal. The first matching rule wins; otherwise mail stays in place. Spam is an ordinary recipe, never an automatic or reserved rule.

Press `l` with a message selected to choose an existing semantic rule and preview a deterministic matcher proposal. Saving changes only the rules file, after fit, safety, duplicate, conflict, and stale-fingerprint checks. The example message is not moved. Config Ledger cannot be a learning source.

`clean FOLDER` is a deprecated CLI adapter, not a separate TUI workflow. The TUI has no Legacy Clean screen or binding.

## System, operations, and privacy

`s` opens System for connection setup, effective-config inspection, explicit connect/disconnect, and credential workflows. Setup edits IMAP connection and authentication settings only; it has no mail automation or Spam controls. Secrets are not shown in forms or operation output. `:` opens Command Center, which searches the operation inventory and explains unavailable requirements. `G` opens Config Ledger for snapshots, diffs, pulls, and pushes. Pull previews bind the target and snapshot hashes; overwrites require explicit confirmation.

The visual-content panel counts embedded images and remote HTML image references locally. `i` explicitly analyzes eligible embedded images; results are informational and do not affect routing. Remote images are never fetched automatically. `I` opens a cancel-default confirmation; loading can reveal the user's network address to external hosts. Requests use strict HTTPS, DNS/IP, redirect, timeout, and response-size checks. URLs and downloaded bytes are not persisted.
