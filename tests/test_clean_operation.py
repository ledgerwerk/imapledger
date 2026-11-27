from __future__ import annotations

from types import SimpleNamespace

import pytest

from imapledger.application.clean import CleanOperation, CleanRequest
from imapledger.config import ImapSettings, Settings, SpamSettings
from imapledger.routing_models import RoutingRule, RuleSet, RuleType
from imapledger.rules import RuleMatch


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=()),
    )


def _rules() -> RuleSet:
    return RuleSet(
        (
            RoutingRule(
                id="invoice",
                enabled=True,
                type=RuleType.HEADER,
                destination="Invoices",
                match=RuleMatch(subject="invoice"),
            ),
        ),
    )


class _Mailbox:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def __enter__(self) -> _Mailbox:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Engine:
    report: object
    kwargs: dict[str, object] = {}

    def __init__(self, **_: object) -> None:
        pass

    def run(self, mailbox: _Mailbox, **kwargs: object) -> object:
        type(self).kwargs = kwargs
        return self.report


def test_clean_preflight_does_not_require_a_fallback_destination() -> None:
    operation = CleanOperation(_settings(), _rules())

    result = operation.preflight(CleanRequest(folder="INBOX"))

    assert result.mode == "full"
    assert result.destinations == ("Invoices",)


def test_clean_preflight_limits_destinations_to_selected_enabled_rule() -> None:
    operation = CleanOperation(_settings(), _rules())

    result = operation.preflight(CleanRequest(folder="INBOX", rule_scope="invoice"))

    assert result.folder == "INBOX"
    assert result.mode == "single-rule"
    assert result.destinations == ("Invoices",)


def test_clean_operation_passes_request_and_reports_touched_folders(monkeypatch, tmp_path) -> None:
    report = SimpleNamespace(
        messages=(
            SimpleNamespace(destination="Invoices", confirmed=True),
            SimpleNamespace(destination="Archive", confirmed=False),
        )
    )
    _Engine.report = report
    monkeypatch.setattr("imapledger.application.clean.ProcessingEngine", _Engine)
    mailboxes: list[_Mailbox] = []
    stores: list[object] = []

    def mailbox_factory(**kwargs: object) -> _Mailbox:
        mailbox = _Mailbox(**kwargs)
        mailboxes.append(mailbox)
        return mailbox

    operation = CleanOperation(
        _settings(),
        _rules(),
        mailbox_factory=mailbox_factory,
        progress_store_factory=lambda path: stores.append(path) or object(),
    )
    request = CleanRequest(folder="INBOX", apply=True, limit=10, progress_db=tmp_path / "progress.db")

    result = operation.run(request, password="secret")

    assert stores == [tmp_path / "progress.db"]
    assert mailboxes[0].kwargs["allowed_destinations"] == ("Invoices",)
    assert mailboxes[0].kwargs["writable"] is True
    assert result.report is report
    assert result.touched_folders == ("INBOX", "Invoices")
    assert _Engine.kwargs == {
        "apply": True,
        "limit": 10,
        "rule_scope": None,
        "sort_direction": "oldest",
        "new_run": False,
        "retry_errors": False,
        "on_result": None,
        "should_stop": None,
    }


def test_clean_request_rejects_unsafe_option_combinations() -> None:
    with pytest.raises(ValueError, match="--retry-errors requires --apply"):
        CleanRequest(folder="INBOX", retry_errors=True)

    with pytest.raises(ValueError, match="cannot be combined"):
        CleanRequest(folder="INBOX", apply=True, new_run=True, retry_errors=True)
