from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .mailbox import PartialMoveError, ScopedMailbox
from .preflight import preflight_source
from .routing_config import rules_fingerprint
from .routing_models import EvaluationState, RoutingAction, RoutingPlan, RuleSet


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
    ) -> RoutingActionReceipt:
        receipt = RoutingActionReceipt(plan, uidvalidity, applied=False, confirmed=False)
        if not confirmed_by_user:
            return self._with_detail(receipt, "User confirmation is required; no changes made.")
        try:
            rules = self._current_rules()
            self._validate_plan(plan, rules)
        except Exception as exc:
            return self._with_detail(receipt, str(exc))

        destination = plan.destination
        if destination is None:
            return self._with_detail(receipt, "Routing plan has no MOVE destination; no changes made.")
        if plan.action is RoutingAction.ALREADY_THERE:
            return self._with_detail(receipt, "Already in destination; no changes made.")
        settings = self._settings
        check = self._preflight(
            settings,
            plan.folder,
            password=self._password,
            destinations=(destination,),
            requires_delete=False,
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
                writable=True,
                allowed_destinations=(destination,),
                max_message_bytes=settings.spam.max_message_bytes,
                max_body_chars=settings.spam.max_body_chars,
                uid_scope=(plan.uid,),
            ) as mailbox:
                snapshot = mailbox.snapshot()
                if snapshot.uidvalidity != uidvalidity:
                    return self._with_detail(
                        receipt,
                        "UIDVALIDITY changed since analysis; classify again before applying.",
                    )
                if plan.uid not in snapshot.uids:
                    return self._with_detail(receipt, "Message UID is no longer in the source folder; no changes made.")
                self._validate_plan(plan, self._current_rules())
                move_result = mailbox.move_uid(plan.uid, destination)
                confirmed = plan.uid in move_result.moved
                return RoutingActionReceipt(
                    plan,
                    uidvalidity,
                    applied=confirmed,
                    confirmed=confirmed,
                    detail=None if confirmed else "Server did not confirm the requested MOVE.",
                )
        except PartialMoveError as exc:
            moved = getattr(exc, "moved", ())
            confirmed = plan.uid in moved
            return RoutingActionReceipt(
                plan,
                uidvalidity,
                applied=confirmed,
                confirmed=confirmed,
                detail=f"PartialMoveError: {exc}",
            )
        except Exception as exc:
            return self._with_detail(receipt, f"{type(exc).__name__}: {exc}")

    def _current_rules(self) -> RuleSet:
        return self._rules_provider() if self._rules_provider is not None else self._rules

    def _validate_plan(self, plan: RoutingPlan, rules: RuleSet) -> None:
        settings = self._settings
        config_store = settings.config_store.folder if settings.config_store is not None else None
        rules.validate_destinations(plan.folder, config_store_folder=config_store)
        fingerprint = rules_fingerprint(
            rules,
            spam_policy=settings.spam.policy.thresholds(),
            spam_evidence_config={
                "trusted_authserv_ids": list(settings.spam.trusted_authserv_ids),
                "trusted_provider_headers": list(settings.spam.trusted_provider_headers),
            },
        )
        if plan.rules_fingerprint != fingerprint:
            raise ValueError("Rules changed since this plan was created; classify again before applying.")
        if any(result.state is EvaluationState.ERROR for result in plan.rule_results):
            raise ValueError("Routing plan contains an evaluation error; no action is authorized.")
        if plan.destination is None:
            return
        if plan.winner_rule_id is not None:
            winner = next((rule for rule in rules.enabled_rules(plan.folder) if rule.id == plan.winner_rule_id), None)
            if winner is None or winner.destination != plan.destination:
                raise ValueError("Winning rule or destination is no longer configured; classify again.")
        elif plan.winner_rule_id is None:
            raise ValueError("Plan destination is not the configured destination of a current rule.")
        if config_store is not None and plan.destination == config_store:
            raise ValueError("Config-store folder cannot be a routing destination.")

    @staticmethod
    def _with_detail(receipt: RoutingActionReceipt, detail: str) -> RoutingActionReceipt:
        return RoutingActionReceipt(
            receipt.plan,
            receipt.uidvalidity,
            applied=receipt.applied,
            confirmed=receipt.confirmed,
            detail=detail,
        )
