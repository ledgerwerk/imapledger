from __future__ import annotations

from enum import Enum


class RuleAction(str, Enum):
    MOVE = "move"
    DELETE = "delete"
    KEEP = "keep"
