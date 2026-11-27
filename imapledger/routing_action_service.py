from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .mailbox import PartialDeleteError, PartialMoveError, ScopedMailbox
from .preflight import preflight_source
from .routing_actions import RuleAction
from .routing_config import rules_fingerprint
from .routing_models import EvaluationState, RoutingPlan, RuleSet


@dataclass(frozen=True, slots=True)
class RoutingActionReceipt:
    plan: RoutingPlan
    uidvalidity: int
    applied: bool
    confirmed: bool
    detail: str | None = None


class RoutingActionService:
    """Apply only a current, confirmed routing plan to its exact message UID."""

    def __init__(
        self,
        settings: Settings,
        password: str,
        rules: RuleSet,
        *,
        rules_provider: Callable[[], RuleSet] | None = None,
        mailbox_factory: Any = ScopedMailbox,
        preflight: Any = preflight_source,
    ) -> None:
        self._settings = settings
        self._password = password
        self._rules = rules
        self._rules_provider = rules_provider
        self._mailbox_factory = mailbox_factory
        self._preflight = preflight

    def set_rules(self, rules: RuleSet) -> None:
        self._rules = rules

    def set_settings(self, settings: Settings) -> None:
        self._settings = settings

    def close(self) -> None:
        self._password = ""

    def apply(
        self,
        plan: RoutingPlan,
        *,
        uidvalidity: int,
        confirmed_by_user: bool,
        allow_delete: bool = False,
    ) -> RoutingActionReceipt:
        receipt = RoutingActionReceipt(plan, uidvalidity, applied=False, confirmed=False)
        if not isinstance(confirmed_by_user, bool):
            raise ValueError("confirmed_by_user must be a boolean")
        if not isinstance(allow_delete, bool):
            raise ValueError("allow_delete must be a boolean")
        if not confirmed_by_user:
            return self._with_detail(receipt, "User confirmation is required; no changes made.")
        try:
            rules = self._current_rules()
            self._validate_plan(plan, rules)
        except Exception as exc:
            return self._with_detail(receipt, str(exc))

        if plan.winner_rule_id is None or plan.configured_action is None:
            return self._with_detail(receipt, "No rule matched; no action is required.")
        action = plan.configured_action
        if action is RuleAction.DELETE and not allow_delete:
            return self._with_detail(receipt, "DELETE requires explicit --allow-delete authorization; no changes made.")
        if action is RuleAction.MOVE and plan.destination is None:
            return self._with_detail(receipt, "MOVE plan has no destination; no changes made.")

        destination = plan.destination
        already_there = action is RuleAction.MOVE and destination == plan.folder
        destinations = (destination,) if action is RuleAction.MOVE and not already_there and destination else ()
        requires_delete = action is RuleAction.DELETE
        settings = self._settings
        check = self._preflight(
            settings,
            plan.folder,
            password=self._password,
            destinations=destinations,
            requires_delete=requires_delete,
            uid_scope=(plan.uid,),
            deep_probe=False,
            mailbox_factory=self._mailbox_factory,
        )
        if not check.ok:
            details = "; ".join(str(error) for error in check.errors) or "mailbox preflight rejected the plan"
            return self._with_detail(receipt, details)

        try:
            with self._mailbox_factory(
                host=settings.imap.host,
                port=settings.imap.port,
                username=settings.imap.username,
                password=self._password,
                folder=plan.folder,
                writable=action is not RuleAction.KEEP and not already_there,
                allowed_destinations=destinations,
                allow_delete=requires_delete,
                max_message_bytes=settings.mail.max_message_bytes,
                max_body_chars=settings.mail.max_body_chars,
                uid_scope=(plan.uid,),
            ) as mailbox:
                snapshot = mailbox.snapshot()
                if snapshot.uidvalidity != uidvalidity:
                    return self._with_detail(
                        receipt,
                        "UIDVALIDITY changed since analysis; evaluate the message again before applying.",
                    )
                if plan.uid not in snapshot.uids:
                    return self._with_detail(receipt, "Message UID is no longer in the source folder; no changes made.")
                self._validate_plan(plan, self._current_rules())
                if action is RuleAction.KEEP:
                    return RoutingActionReceipt(
                        plan,
                        uidvalidity,
                        applied=True,
                        confirmed=True,
                        detail="Message kept in place; no mailbox mutation was required.",
                    )
                if already_there:
                    return RoutingActionReceipt(
                        plan,
                        uidvalidity,
                        applied=True,
                        confirmed=True,
                        detail="Message is already in the configured destination.",
                    )
                if action is RuleAction.MOVE:
                    assert destination is not None
                    result = mailbox.move_uid(plan.uid, destination)
                    confirmed = plan.uid in result.moved
                    return RoutingActionReceipt(
                        plan,
                        uidvalidity,
                        applied=confirmed,
                        confirmed=confirmed,
                        detail=None if confirmed else "Server did not confirm the requested MOVE.",
                    )
                result = mailbox.delete_uid(plan.uid)
                confirmed = plan.uid in result.deleted
                return RoutingActionReceipt(
                    plan,
                    uidvalidity,
                    applied=confirmed,
                    confirmed=confirmed,
                    detail=None if confirmed else "Server did not confirm the requested DELETE.",
                )
        except (PartialMoveError, PartialDeleteError) as exc:
            completed = getattr(exc, "moved", getattr(exc, "deleted", ()))
            confirmed = plan.uid in completed
            return RoutingActionReceipt(
                plan,
                uidvalidity,
                applied=confirmed,
                confirmed=confirmed,
                detail=f"{type(exc).__name__}: {exc}",
            )
        except Exception as exc:
            return self._with_detail(receipt, f"{type(exc).__name__}: {exc}")

    def _current_rules(self) -> RuleSet:
        return self._rules_provider() if self._rules_provider is not None else self._rules

    def _validate_plan(self, plan: RoutingPlan, rules: RuleSet) -> None:
        settings = self._settings
        config_store = settings.config_store.folder if settings.config_store is not None else None
        rules.validate_destinations(plan.folder, config_store_folder=config_store)
        if plan.rules_fingerprint != rules_fingerprint(rules):
            raise ValueError("Rules changed since this plan was created; evaluate the message again before applying.")
        if any(result.state is EvaluationState.ERROR for result in plan.rule_results):
            raise ValueError("Routing plan contains an evaluation error; no action is authorized.")

        candidates = rules.enabled_rules(plan.folder)
        if plan.mode == "single-rule":
            if plan.rule_scope is None:
                raise ValueError("Single-rule plan has no rule scope; evaluate the message again.")
            candidate = next((rule for rule in candidates if rule.id == plan.rule_scope), None)
            candidates = (candidate,) if candidate is not None else ()
        elif plan.mode != "full":
            raise ValueError("Unknown routing plan mode.")
        if tuple(result.rule_id for result in plan.rule_results) != tuple(rule.id for rule in candidates):
            raise ValueError("Evaluated rules do not match the current rule scope; evaluate the message again.")

        first_match = next(
            (result.rule_id for result in plan.rule_results if result.state is EvaluationState.MATCH),
            None,
        )
        if first_match != plan.winner_rule_id:
            raise ValueError("Winning rule does not match the first evaluated rule; evaluate the message again.")
        if plan.winner_rule_id is None:
            if plan.configured_action is not None or plan.destination is not None:
                raise ValueError("No-match plan contains a configured action; evaluate the message again.")
            return

        winner = next((rule for rule in candidates if rule.id == plan.winner_rule_id), None)
        if winner is None or winner.action is not plan.configured_action or winner.destination != plan.destination:
            raise ValueError("Winning rule action or destination changed; evaluate the message again.")
        if winner.action is not RuleAction.MOVE and plan.destination is not None:
            raise ValueError("Non-MOVE plan must not contain a destination.")

    @staticmethod
    def _with_detail(receipt: RoutingActionReceipt, detail: str) -> RoutingActionReceipt:
        return RoutingActionReceipt(
            receipt.plan,
            receipt.uidvalidity,
            applied=receipt.applied,
            confirmed=receipt.confirmed,
            detail=detail,
        )
