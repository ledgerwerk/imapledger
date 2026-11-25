# Interactive mail review console

Launch the terminal user interface with:

```bash
imapledger ui
```

The console has three panes: folders and smart views, the message list, and message detail. Opening a message uses the existing read-only `BODY.PEEK` path. HTML is not rendered, attachments are not opened, and selecting a message does not mark it seen.

## Keyboard shortcuts

| Key                    | Action                                                           |
| ---------------------- | ---------------------------------------------------------------- |
| Left / `H`             | Focus the previous pane; Left stops at the first pane            |
| Right / `L`            | Focus the next pane; Right stops at the last pane                |
| Tab / Shift+Tab        | Cycle focus forward / backward through panes                     |
| Up / Down or `k` / `j` | Move through folders or messages; scroll message detail          |
| `g` / `G`              | First / last item, or top / bottom of message detail             |
| Home / End             | First / last item, or top / bottom of message detail             |
| PageUp / PageDown      | Page through the focused pane                                    |
| Enter                  | Open the selected folder or message                              |
| `c` / `C`              | Classify / reclassify the selected message                       |
| `i`                    | Explicitly analyze eligible embedded images                      |
| `I`                    | Review and optionally load remote images after confirmation      |
| `a`                    | Apply the configured action; a separate confirmation is required |
| `R`                    | Open the Rule Center                                             |
| `r`                    | Refresh                                                          |
| `h` / `?`              | Open keyboard help (`h`, Escape, or `q` closes help)             |
| `q`                    | Quit                                                             |

Pane navigation follows the widget that currently has focus, including focus reached with the mouse. The focused pane has a highlighted border. The in-app help screen is available at any time with `h`.

## Actions, policies, and routing rules

Press `a` with a message selected to open the Action Center. The analysis panel distinguishes the semantic classifier's outcome and verdict from the configured outcome policy, a deterministic routing-rule match, and the mailbox action. A verdict is not itself a mail operation. The Action Center lets you choose KEEP, MOVE, or DELETE for the current message, or edit global SPAM, NOT_SPAM, and REVIEW actions.

Applying an action always requires a separate confirmation that names the folder and exact UID. MOVE shows its destination. DELETE is permanent and warns about UID EXPUNGE. Choosing or editing policy does not act on messages; a global SPAM DELETE change affects only later explicit apply operations and requires its own additional confirmation. MOVE destinations are existing folders; the TUI does not create folders or expand `spam.folders`.

Press `R` to open the Rule Center. It supports structured rule creation and editing, enable/disable, priority reordering, details, bounded read-only testing, and confirmed removal. Rules are local and deterministic, use only KEEP or MOVE, and never use Jev for manual creation or testing. Rule source folders must remain within configured `spam.folders`, and MOVE destinations must already exist and cannot be configured source folders.

Saving rule changes reloads them into the running session and refreshes analysis of the selected message. Save-only changes local rule configuration but does not mutate mail. Save-and-apply is a separate operation: after saving, the TUI re-resolves the selected folder and UID and requests confirmation before applying only to that message. Rule tests are read-only and bounded.

## Image inventory and visual analysis

The visual-content section counts embedded images and remote HTML image references as soon as the message is opened. This inventory is local. Opening a message does not contact remote image hosts or send image bytes to `pyjev`.

Press `i` to explicitly assess eligible embedded images. Preparation and model work run in the background. Results include the image's role, importance, whether visible text is insufficient, actionable/financial relevance, interest dependence, and a deterministic local recommendation. Unsupported, malformed, oversized, or otherwise ineligible images are reported as skipped. Analysis reports are cached in memory for the current session using folder, UIDVALIDITY, and UID; they are not written to disk or IMAP.

Visual recommendations are reading aids only. They do not change spam outcomes, persisted classification state, configured actions, or message flags. They do not open links or perform mail actions. The `c` and `C` classification keys remain separate from `i`.

## Remote image privacy

Remote image references are never fetched automatically. Pressing `I` opens a confirmation screen with Cancel focused by default. Loading an image contacts its external host and may reveal that the message was opened and the user's network address. Canceling makes no remote request.

After confirmation, the loader accepts only credential-free HTTPS URLs on the standard HTTPS port. It resolves each hostname, rejects non-public addresses, pins the connection to a validated address, and revalidates every redirect target. Requests have bounded connect/read timeouts, a small redirect limit, an image-count limit, and an 8 MB response limit per image. Only PNG/JPEG responses are accepted. The loader sends no cookies, Authorization header, or Referer, does not use a proxy, execute, or render downloaded content, and reports failures per image. Accepted bytes are passed through local image preparation before visual analysis. URLs and downloaded bytes are not persisted; the visual report alone may be retained in the in-memory session cache.

The `a` key remains the only TUI path to apply a configured mail action, and its confirmation is independent of visual analysis.
