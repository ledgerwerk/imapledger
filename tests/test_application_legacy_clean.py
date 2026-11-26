from __future__ import annotations

from types import SimpleNamespace

import pytest

from imapledger.application.legacy_clean import LegacyCleanOperation, LegacyCleanRequest
from imapledger.classification_state import SpamOutcome
from imapledger.cleaner import CleanReport, MessageResult
from imapledger.config import ConfigError, ImapSettings, Settings, SpamSettings
from imapledger.mailbox import MessageSort
from imapledger.preflight import SourcePreflightResult
from imapledger.rules import RuleSet


def _settings(folders: tuple[str, ...] = ("Spam", "Junk")) -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=folders),
    )


def test_legacy_clean_request_defaults_to_preview_and_validates_scope_options() -> None:
    request = LegacyCleanRequest()

    assert not request.apply
    assert request.sort is MessageSort.NEWEST
    assert request.limit is None
    assert request.offset == 0
    with pytest.raises(ValueError, match="positive integer"):
        LegacyCleanRequest(limit=0)
    with pytest.raises(ValueError, match="non-negative integer"):
        LegacyCleanRequest(offset=-1)
    with pytest.raises(ValueError, match="MessageSort"):
        LegacyCleanRequest(sort="newest")


def test_legacy_clean_preflight_covers_every_configured_source_only_for_apply() -> None:
    calls = []

    def fake_preflight(settings, folder, **kwargs):
        calls.append((settings, folder, kwargs))
        return SourcePreflightResult(
            folder=folder,
            opened=True,
            probe=None,
            capabilities=frozenset(),
            missing_capabilities=(),
            destinations=(),
            errors=(),
        )

    operation = LegacyCleanOperation(_settings(), RuleSet(), preflight=fake_preflight)
    assert operation.preflight(LegacyCleanRequest(), password="secret") == ()
    results = operation.preflight(LegacyCleanRequest(apply=True), password="secret")

    assert [folder for _, folder, _ in calls] == ["Spam", "Junk"]
    assert all(kwargs["password"] == "secret" for _, _, kwargs in calls)
    assert [result.folder for result in results] == ["Spam", "Junk"]
    assert all(result.ok for result in results)


def test_legacy_clean_preview_reuses_cleaner_and_streams_folder_scoped_results(monkeypatch) -> None:
    settings = _settings()
    callbacks = []
    folder_starts = []

    class FakeMailbox:
        def __init__(self, **kwargs):
            self.folder = kwargs["folder"]

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def snapshot(self):
            return SimpleNamespace(uids=(10, 20))

        def selected_count(self, _selection):
            return 2

    class FakeClassifier:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    row = MessageResult(
        uid=10,
        subject="private subject",
        sender="private@example.org",
        verdict=None,
        signals=None,
        reasons=(),
        status="keep",
        inclination="KEEP",
        outcome=SpamOutcome.NOT_SPAM,
    )

    class FakeCleaner:
        def __init__(self, mailbox, _classifier, **_kwargs):
            self.folder = mailbox.folder

        def run(self, *, apply, selection, on_result, reclassify):
            if on_result is not None:
                on_result(row, 1, 1)
            return CleanReport(folder=self.folder, apply=apply, results=[row])

    monkeypatch.setattr("imapledger.application.legacy_clean.SpamCleaner", FakeCleaner)
    operation = LegacyCleanOperation(
        settings,
        RuleSet(),
        mailbox_factory=FakeMailbox,
        classifier_factory=FakeClassifier,
    )
    result = operation.run(
        LegacyCleanRequest(limit=5, offset=1, sort=MessageSort.OLDEST),
        password="secret",
        on_folder_start=lambda *args: folder_starts.append(args),
        on_result=lambda *args: callbacks.append(args),
    )

    assert [report.folder for report in result.reports] == ["Spam", "Junk"]
    assert [item[0] for item in folder_starts] == ["Spam", "Junk"]
    assert [item[0] for item in callbacks] == ["Spam", "Junk"]
    assert all(item[1].subject == "private subject" for item in callbacks)
    assert not result.preflight_failed
    assert result.failure is None


def test_legacy_clean_apply_stops_when_any_source_preflight_fails() -> None:
    def fake_preflight(_settings, folder, **_kwargs):
        return SourcePreflightResult(
            folder=folder,
            opened=False,
            probe=None,
            capabilities=frozenset(),
            missing_capabilities=(),
            destinations=(),
            errors=(RuntimeError("preflight failed"),),
        )

    operation = LegacyCleanOperation(_settings(), RuleSet(), preflight=fake_preflight)
    result = operation.run(LegacyCleanRequest(apply=True), password="secret")

    assert result.preflight_failed
    assert result.reports == ()
    assert result.failure is None


def test_legacy_clean_requires_configured_source_folders() -> None:
    operation = LegacyCleanOperation(_settings(()), RuleSet())

    with pytest.raises(ConfigError, match="spam.folders"):
        operation.validate_config()
