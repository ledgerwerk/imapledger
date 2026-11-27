from __future__ import annotations

from typing import Generic, TypeVar

from rich.text import Text
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widget import Widget

ResultT = TypeVar("ResultT")


class KeyboardHint(Widget):
    can_focus = False

    def __init__(self, text: str) -> None:
        super().__init__(classes="keyboard-modal-hint")
        self._text = text

    def render(self) -> Text:
        return Text(self._text)


class KeyboardModalScreen(ModalScreen[ResultT], Generic[ResultT]):
    """Modal screen with explicit, contained keyboard focus traversal."""

    KEYBOARD_HINT = "Tab/Shift+Tab navigate · Enter activate focused control · Esc cancel or close"

    CSS = """
    KeyboardModalScreen Button:focus {
        text-style: bold;
    }
    KeyboardModalScreen ListView:focus,
    KeyboardModalScreen DataTable:focus {
        border: round $accent;
    }
    .keyboard-modal-hint {
        dock: bottom;
        height: 1;
        width: 100%;
        text-align: center;
        color: $text-muted;
        background: $surface;
    }
    """

    def on_mount(self) -> None:
        self.mount(KeyboardHint(self.KEYBOARD_HINT))

    BINDINGS = [
        Binding("tab", "focus_next_control", show=False, priority=True),
        Binding("shift+tab", "focus_previous_control", show=False, priority=True),
    ]

    def action_focus_next_control(self) -> None:
        self.focus_next()

    def action_focus_previous_control(self) -> None:
        self.focus_previous()
