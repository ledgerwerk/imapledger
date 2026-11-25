from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .analysis_service import MessageAnalysis
from .classification_state import ClassificationStateBackend, all_state_keywords, keyword_for_outcome
from .config import ActionKind, MessageAction, Settings, action_for_outcome
from .mailbox import PartialDeleteError, PartialMoveError, ScopedMailbox
from .preflight import preflight_source


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    folder: str
    uidvalidity: int
    uid: int
    requested_action: MessageAction
    outcome: str | None
    decision_source: str
    applied: bool
    confirmed: bool
    destination: str | None = None
    state_keyword: str | None = None
    detail: str | None = None


class ActionService:
    """Apply one configured classification action to one exact selected message."""

    def __init__(
        self,
        settings: Settings,
        password: str,
        *,
        mailbox_factory: Any = ScopedMailbox,
        preflight: Any = preflight_source,
    ) -> None:
        self._settings = settings
        self._password = password
        self._mailbox_factory = mailbox_factory
        self._preflight = preflight

    def set_settings(self, settings: Settings) -> None:
        self._settings = settings

    def close(self) -> None:
        self._password = ""

    def apply(
        self,
        analysis: MessageAnalysis,
        *,
        uidvalidity: int,
        confirmed_by_user: bool,
    ) -> ActionReceipt:
        folder = analysis.folder
        uid = analysis.uid
        action = analysis.configured_action
        if action is None:
            raise ValueError("analysis does not contain a configured action")
        if not self._is_configured_action(analysis, action):
            raise ValueError("refusing an action that is not configured for this message")

        receipt = ActionReceipt(
            folder=folder,
            uidvalidity=uidvalidity,
            uid=uid,
            requested_action=action,
            outcome=analysis.outcome.value if analysis.outcome is not None else None,
            decision_source=analysis.decision_source,
            applied=False,
            confirmed=False,
            destination=action.destination,
        )
        if not confirmed_by_user:
            return replace(receipt, detail="User confirmation is required; no changes made.")

        destinations = (action.destination,) if action.action is ActionKind.MOVE else ()
        requires_delete = action.action is ActionKind.DELETE
        state_keyword = None
        state_required = (
            action.action is ActionKind.KEEP
            and analysis.outcome is not None
            and self._settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS
        )
        if state_required:
            state_keyword = keyword_for_outcome(analysis.outcome)

        check = self._preflight(
            self._settings,
            folder,
            password=self._password,
            destinations=(action.destination,) if action.action is ActionKind.MOVE and action.destination else (),
            requires_delete=requires_delete,
            require_state_persistence=state_required,
            uid_scope=(),
            deep_probe=False,
            mailbox_factory=self._mailbox_factory,
        )
        if not check.ok:
            details = "; ".join(str(error) for error in check.errors) or "mailbox preflight rejected the action"
            return replace(receipt, detail=details, state_keyword=state_keyword)

        try:
            with self._mailbox_factory(
                host=self._settings.imap.host,
                port=self._settings.imap.port,
                username=self._settings.imap.username,
                password=self._password,
                folder=folder,
                writable=True,
                allowed_destinations=destinations,
                allow_delete=requires_delete,
                max_message_bytes=self._settings.spam.max_message_bytes,
                max_body_chars=self._settings.spam.max_body_chars,
                uid_scope=(uid,),
            ) as mailbox:
                snapshot = mailbox.snapshot()
                if snapshot.uidvalidity != uidvalidity:
                    return replace(
                        receipt,
                        detail="UIDVALIDITY changed since the message was selected; no changes made.",
                        state_keyword=state_keyword,
                    )
                if uid not in snapshot.uids:
                    return replace(
                        receipt,
                        detail="Message UID is no longer in the current mailbox snapshot; no changes made.",
                        state_keyword=state_keyword,
                    )
                if action.action is ActionKind.MOVE and folder == action.destination:
                    return replace(
                        receipt,
                        applied=True,
                        confirmed=True,
                        detail=(
                            f"Message already resides in configured destination {action.destination}. "
                            "No mailbox mutation required."
                        ),
                    )
                if action.action is ActionKind.MOVE:
                    result = mailbox.move_uid(uid, action.destination)
                    confirmed = uid in result.moved
                elif action.action is ActionKind.DELETE:
                    result = mailbox.delete_uid(uid)
                    confirmed = uid in result.deleted
                else:
                    if state_keyword is not None:
                        mailbox.set_classification_keyword(
                            uid,
                            keyword=state_keyword,
                            peer_keywords=tuple(
                                keyword for keyword in all_state_keywords() if keyword != state_keyword
                            ),
                        )
                    confirmed = True
                return replace(
                    receipt,
                    applied=confirmed,
                    confirmed=confirmed,
                    state_keyword=state_keyword,
                    detail=None if confirmed else "Server did not confirm the requested action.",
                )
        except (PartialMoveError, PartialDeleteError) as exc:
            completed = getattr(exc, "moved", getattr(exc, "deleted", ()))
            confirmed = uid in completed
            return replace(
                receipt,
                applied=confirmed,
                confirmed=confirmed,
                state_keyword=state_keyword,
                detail=f"{type(exc).__name__}: {exc}",
            )
        except Exception as exc:
            return replace(
                receipt,
                state_keyword=state_keyword,
                detail=f"{type(exc).__name__}: {exc}",
            )

    def _is_configured_action(self, analysis: MessageAnalysis, action: MessageAction) -> bool:
        if analysis.outcome is None:
            return False
        return action == action_for_outcome(self._settings, analysis.outcome)
