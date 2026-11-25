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
| `R`                    | Open global Classification Rules for SPAM, NOT_SPAM, and REVIEW  |
| `F`                    | Open optional advanced Routing Filters                           |
| `r`                    | Refresh                                                          |
| `h` / `?`              | Open keyboard help (`h`, Escape, or `q` closes help)             |
| `q`                    | Quit                                                             |

Pane navigation follows the widget that currently has focus, including focus reached with the mouse. The focused pane has a highlighted border. The in-app help screen is available at any time with `h`.

## Classification actions and advanced routing filters

Press `a` with a message selected to apply the configured action for its SPAM, NOT_SPAM, or REVIEW category. The analysis panel distinguishes the classification category from the classifier's verdict and shows the configured action. Advanced routing filters are separate from category classification and are not part of the manual apply flow.

Applying a category action requires confirmation naming the exact folder and UID. It works for a deliberately selected message in any selectable mailbox folder, regardless of `spam.folders`. MOVE shows its destination. DELETE is permanent and warns about UID EXPUNGE. Saving an action does not change existing mail. SPAM DELETE changes the global action for future SPAM classifications and has its own confirmation. MOVE destinations must already exist.

Press `R` to open Classification Rules. Edit the global action for each category, SPAM, NOT_SPAM, and REVIEW. The screen also lists automatic clean folders and explains that they limit unattended batch processing only. Saving an action updates configuration and the running session without mutating mail.

Press `F` to open optional advanced Routing Filters. These preserve the existing `rules.toml` format and support structured rule creation, editing, enable/disable, priority reordering, details, bounded read-only testing, and confirmed removal. They remain scoped to configured `spam.folders` and are used by batch `clean`, not by manual classification or `mail classify`. Rules use KEEP or MOVE only, and MOVE destinations must already exist.

## Image inventory and visual analysis

The visual-content section counts embedded images and remote HTML image references as soon as the message is opened. This inventory is local. Opening a message does not contact remote image hosts or send image bytes to `pyjev`.

Press `i` to explicitly assess eligible embedded images. Preparation and model work run in the background. Results include the image's role, importance, whether visible text is insufficient, actionable/financial relevance, interest dependence, and a deterministic local recommendation. Unsupported, malformed, oversized, or otherwise ineligible images are reported as skipped. Analysis reports are cached in memory for the current session using folder, UIDVALIDITY, and UID; they are not written to disk or IMAP.

Visual recommendations are reading aids only. They do not change spam outcomes, persisted classification state, configured actions, or message flags. They do not open links or perform mail actions. The `c` and `C` classification keys remain separate from `i`.

## Remote image privacy

Remote image references are never fetched automatically. Pressing `I` opens a confirmation screen with Cancel focused by default. Loading an image contacts its external host and may reveal that the message was opened and the user's network address. Canceling makes no remote request.

After confirmation, the loader accepts only credential-free HTTPS URLs on the standard HTTPS port. It resolves each hostname, rejects non-public addresses, pins the connection to a validated address, and revalidates every redirect target. Requests have bounded connect/read timeouts, a small redirect limit, an image-count limit, and an 8 MB response limit per image. Only PNG/JPEG responses are accepted. The loader sends no cookies, Authorization header, or Referer, does not use a proxy, execute, or render downloaded content, and reports failures per image. Accepted bytes are passed through local image preparation before visual analysis. URLs and downloaded bytes are not persisted; the visual report alone may be retained in the in-memory session cache.

The `a` key remains the only TUI path to apply a configured mail action, and its confirmation is independent of visual analysis.
