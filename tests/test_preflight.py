from __future__ import annotations

from types import SimpleNamespace

import pytest

from imapledger.application.clean import CleanOperation, CleanRequest
from imapledger.config import ImapSettings, MailSettings, Settings
from imapledger.preflight import preflight_source
from imapledger.routing_actions import RuleAction
from imapledger.routing_models import RoutingRule, RuleSet, RuleType
from imapledger.rules import RuleMatch


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        mail=MailSettings(max_message_bytes=1234, max_body_chars=5678),
    )


class _Mailbox:
    def __init__(self, capabilities: frozenset[bytes]) -> None:
        self.capabilities = capabilities

    def __enter__(self) -> _Mailbox:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def snapshot(self) -> SimpleNamespace:
        return SimpleNamespace(permanent_flags=frozenset(), permanent_flags_known=False)

    def destination_exists(self, _folder: str) -> bool:
        return False

    def probe(self) -> None:
        return None


def test_delete_preflight_requires_uidplus_and_uses_generic_mail_limits() -> None:
    calls: list[dict[str, object]] = []
    mailbox = _Mailbox(frozenset({b"MOVE"}))

    def factory(**kwargs):
        calls.append(kwargs)
        return mailbox

    result = preflight_source(
        _settings(),
        "INBOX",
        password="secret",
        destinations=(),
        requires_delete=True,
        uid_scope=(9,),
        deep_probe=False,
        mailbox_factory=factory,
    )

    assert result.missing_capabilities == (b"UIDPLUS",)
    assert not result.ok
    assert calls[0]["allow_delete"] is True
    assert calls[0]["max_message_bytes"] == 1234
    assert calls[0]["max_body_chars"] == 5678
    assert calls[0]["uid_scope"] == (9,)


def test_rule_clean_preflight_collects_only_move_destinations_and_delete_requirement() -> None:
    rules = RuleSet(
        (
            RoutingRule(
                "move",
                True,
                RuleType.HEADER,
                action=RuleAction.MOVE,
                destination="Archive",
                match_any=(RuleMatch(from_domain="example.org"),),
            ),
            RoutingRule(
                "keep",
                True,
                RuleType.HEADER,
                action=RuleAction.KEEP,
                match_any=(RuleMatch(list_id="weekly.example"),),
            ),
            RoutingRule(
                "delete",
                True,
                RuleType.HEADER,
                action=RuleAction.DELETE,
                match_any=(RuleMatch(subject="dangerous"),),
            ),
        )
    )
    operation = CleanOperation(_settings(), rules)

    preflight = operation.preflight(CleanRequest("INBOX"))

    assert preflight.destinations == ("Archive",)
    assert preflight.requires_delete is True
    assert preflight.mode == "full"


def test_delete_authorization_flag_is_valid_only_for_apply() -> None:
    with pytest.raises(ValueError, match="requires apply mode"):
        CleanRequest("INBOX", allow_delete=True)
