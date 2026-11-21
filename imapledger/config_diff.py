from __future__ import annotations

from difflib import unified_diff
from enum import Enum


class DiffDirection(str, Enum):
    LOCAL_TO_IMAP = "local-to-imap"
    IMAP_TO_LOCAL = "imap-to-local"


def render_config_diff(
    *,
    local_text: str,
    remote_text: str,
    local_label: str,
    remote_label: str,
    direction: DiffDirection,
) -> str:
    if direction is DiffDirection.LOCAL_TO_IMAP:
        before, after = local_text, remote_text
        from_label, to_label = local_label, remote_label
    else:
        before, after = remote_text, local_text
        from_label, to_label = remote_label, local_label
    return "".join(
        unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=from_label,
            tofile=to_label,
        )
    )
