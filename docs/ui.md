# Interactive mail and rule workbench

Launch the terminal interface with:

```bash
imapledger ui
```

The console provides folder browsing, a message list, bounded plain-text message detail, and current-message routing analysis. It is primarily a rule-development and single-message test workbench. Reading a message uses the read-only `BODY.PEEK` path. HTML is not rendered and attachments are not opened.

## Keyboard shortcuts

| Key                    | Action                                                      |
| ---------------------- | ----------------------------------------------------------- |
| Left / `H`             | Focus the previous pane                                     |
| Right / `L`            | Focus the next pane                                         |
| Tab / Shift+Tab        | Cycle focus through panes                                   |
| Up / Down or `k` / `j` | Move through folders or messages; scroll message detail     |
| `g` / `G`, Home / End  | Move to the first or last item, or top or bottom of detail  |
| PageUp / PageDown      | Page through the focused pane                               |
| Enter                  | Open the selected folder or message                         |
| `c` / `C`              | Analyze or reanalyze the selected message; no mail is moved |
| `R`                    | Open the unified Rules workbench                            |
| `a`                    | Apply the current routing plan after confirmation           |
| `i`                    | Explicitly analyze eligible embedded images                 |
| `I`                    | Review and optionally load remote images after confirmation |
| `r`                    | Refresh                                                     |
| `h` / `?`              | Open keyboard help                                          |
| `q`                    | Quit                                                        |

The focused pane has a highlighted border. Pane navigation follows the widget currently holding focus, including focus reached with the mouse.

## Analyze and apply the exact plan

Press `c` with a message selected to evaluate the current full pipeline. The analysis panel shows each rule's state, semantic confidence where available, the first matching rule or fallback, destination, and rules fingerprint. This is read-only. Use `C` to reanalyze rather than relying on cached classification state in the legacy classification workflow.

Press `a` to apply the current plan. The confirmation names the exact source folder, UID, winning rule or fallback, and destination. Confirmation is bound to the plan and message shown when the dialog opened. Before moving, the application revalidates current rules, UIDVALIDITY, the exact UID, and the configured destination. A stale or invalid plan fails closed. Applying uses configured MOVE destinations only; the TUI does not create folders or issue arbitrary actions.

## Rules workbench

Press `R` to create and edit unified schema-2 rules. Priority is top to bottom, and the first enabled match wins. The workbench can:

- create and edit spam, semantic, or deterministic header rules;
- enable or disable a rule and change its priority;
- configure the full-pipeline fallback destination;
- test the selected rule or evaluate all rules on the current message;
- delete a rule after selection.

Tests are read-only and show rule results, winner, and destination. Saving rule changes updates the local `rules.toml` and refreshes current-message analysis; it does not move existing messages. Rule destinations must be existing mailboxes and cannot be the current source or configuration-ledger folder. Schema-1 files must be explicitly migrated before using the schema-2 workbench. See [Unified routing rules](rules.md).

## Legacy classification actions

Configurations that still use the legacy classification workflow retain category actions for SPAM, NOT_SPAM, and REVIEW. Applying those actions through the TUI is also confirmation-gated. The `spam.folders` list limits bare `clean` compatibility mode, not the explicit-folder routing pipeline. See [Cleaning and diagnostics](cleaning.md) and [Persistent state](state.md).

## Image inventory and visual analysis

The visual-content section counts embedded images and remote HTML image references as soon as the message is opened. This inventory is local. Opening a message does not contact remote image hosts or send image bytes to `pyjev`.

Press `i` to explicitly assess eligible embedded images. Preparation and model work run in the background. Results are reading aids only; they do not change routing rules, destination, persistent classification state, or mail actions. Analysis reports are cached only in memory for the current session.

## Remote image privacy

Remote image references are never fetched automatically. Pressing `I` opens a confirmation screen with Cancel focused by default. Loading an image contacts its external host and may reveal that the message was opened and the user's network address. Canceling makes no remote request.

After confirmation, the loader accepts only credential-free HTTPS URLs on the standard HTTPS port. It resolves each hostname, rejects non-public addresses, pins the connection to a validated address, and revalidates every redirect target. Requests have bounded timeouts, redirect count, image count, and response size. Only PNG/JPEG responses are accepted. The loader sends no cookies, Authorization header, or Referer, does not use a proxy, execute, or render downloaded content. URLs and downloaded bytes are not persisted.
