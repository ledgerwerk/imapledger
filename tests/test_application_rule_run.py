from __future__ import annotations

from types import SimpleNamespace

import pytest

from imapledger.application import (
    RuleApplyMessageOperation,
    RuleEvaluationOperation,
    RuleRunOperation,
    RuleRunRequest,
)
from imapledger.config import ConfigStoreSettings, ImapSettings, Settings, SpamSettings
from imapledger.mailbox import FolderInfo
from imapledger.processing_engine import ProcessedMessage
from imapledger.routing_models import RoutingRule, RuleSet, RuleType
from imapledger.rules import RuleMatch


def _settings(*, config_store: str | None = None) -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=()),
        config_store=ConfigStoreSettings(config_store) if config_store else None,
    )


def _rules() -> RuleSet:
    return RuleSet(
        (
            RoutingRule(
                id="newsletter",
                enabled=True,
                type=RuleType.HEADER,
                destination="Archive",
                match_any=(RuleMatch(list_id="weekly.example.com"),),
            ),
        )
    )


def test_rule_run_preflight_coordinates_global_rules_and_skips_current_destination() -> None:
    operation = RuleRunOperation(_settings(), _rules())

    preflight = operation.preflight(RuleRunRequest(("INBOX", "Archive"), limit=10))

    assert tuple(item.folder for item in preflight.folders) == ("INBOX", "Archive")
    assert tuple(item.destinations for item in preflight.folders) == (("Archive",), ())
    assert preflight.destinations == ("Archive",)


def test_rule_run_refuses_config_ledger_source_folder() -> None:
    operation = RuleRunOperation(_settings(config_store="INBOX.Config"), _rules())

    with pytest.raises(ValueError, match="Config Ledger"):
        operation.preflight(RuleRunRequest(("INBOX.Config",)))


def test_all_folder_scope_excludes_nonselectable_and_config_ledger_folders() -> None:
    folders = (
        FolderInfo("INBOX", ".", frozenset(), None, None),
        FolderInfo("INBOX.Hidden", ".", frozenset({b"\\NOSELECT"}), None, None),
        FolderInfo("INBOX.Config", ".", frozenset(), None, None),
    )
    operation = RuleRunOperation(_settings(config_store="INBOX.Config"), _rules())

    assert operation.selectable_folders(folders) == ("INBOX",)


def test_rule_run_executes_each_folder_through_the_same_operation(monkeypatch, tmp_path) -> None:
    mailboxes: list[dict[str, object]] = []
    callback_results: list[tuple[str, int]] = []

    class Mailbox:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs
            mailboxes.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

    class Engine:
        def __init__(self, **_: object) -> None:
            pass

        def run(self, _mailbox, **kwargs: object):
            message = ProcessedMessage(10, "match", destination="Archive", confirmed=True)
            progress = SimpleNamespace(scanned_count=1)
            on_result = kwargs["on_result"]
            if on_result is not None:
                on_result(message, progress)
            return SimpleNamespace(run=progress, messages=(message,))

    monkeypatch.setattr("imapledger.application.clean.ProcessingEngine", Engine)
    operation = RuleRunOperation(
        _settings(),
        _rules(),
        mailbox_factory=Mailbox,
        progress_store_factory=lambda _path: object(),
    )
    request = RuleRunRequest(("INBOX", "Archive"), apply=True, progress_db=tmp_path / "progress.db")

    result = operation.run(
        request,
        password="secret",
        on_result=lambda folder, message, _progress: callback_results.append((folder, message.uid)),
    )

    assert tuple(kwargs["folder"] for kwargs in mailboxes) == ("INBOX", "Archive")
    assert tuple(folder for folder, _ in result.results) == ("INBOX", "Archive")
    assert callback_results == [("INBOX", 10), ("Archive", 10)]
    assert result.touched_folders == ("INBOX", "Archive")


def test_rule_evaluation_operation_delegates_read_only_evaluation(monkeypatch) -> None:
    message = object()
    plan = object()
    calls: list[tuple[object, object, str | None]] = []

    class Analysis:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def analyze(self, folder, selected, *, rule_scope=None):
            calls.append((folder, selected, rule_scope))
            return plan

        def set_rules(self, _rules) -> None:
            pass

        def set_settings(self, _settings) -> None:
            pass

    monkeypatch.setattr("imapledger.application.rule_run.RoutingAnalysisService", Analysis)
    operation = RuleEvaluationOperation(_settings(), _rules())

    assert operation.evaluate("INBOX", message, rule_scope="newsletter") is plan
    assert calls == [("INBOX", message, "newsletter")]


def test_rule_apply_message_operation_delegates_confirmation_and_uidvalidity() -> None:
    receipt = object()

    class Action:
        def apply(self, plan, *, uidvalidity, confirmed_by_user):
            assert plan is expected_plan
            assert uidvalidity == 7
            assert confirmed_by_user is True
            return receipt

    expected_plan = object()

    operation = RuleApplyMessageOperation(Action())

    assert operation.apply(expected_plan, uidvalidity=7, confirmed_by_user=True) is receipt
