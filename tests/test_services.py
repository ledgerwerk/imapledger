from __future__ import annotations

from imapledger.analysis_service import AnalysisService
from imapledger.classification_state import PersistedState, SpamOutcome
from imapledger.classifier import SemanticSpamSignals, SpamAssessment
from imapledger.config import ImapSettings, MessageAction, Settings, SpamSettings
from imapledger.evidence import build_message_evidence
from imapledger.mail_service import MailService
from imapledger.mailbox import MailboxItem, MessageSort
from imapledger.message import MailSummary, parse_message
from imapledger.policy import SpamVerdict
from imapledger.rules import MailRule, RuleMatch, RuleSet


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("Spam",)),
    )


def _message():
    return parse_message(7, b"From: sender@example.org\r\nSubject: hello\r\n\r\nbody", max_body_chars=100)


def test_analysis_service_uses_persisted_state_without_classifier():
    service = AnalysisService(_settings(), RuleSet(), classifier_factory=lambda **kwargs: None)

    result = service.analyze("Spam", _message(), persisted_outcome=SpamOutcome.REVIEW)

    assert result.decision_source == "persisted-state"
    assert result.outcome is SpamOutcome.REVIEW
    assert result.configured_action == MessageAction(_settings().spam.actions.review.action)
    assert result.signals is None


def test_analysis_service_checks_deterministic_rules_before_classifier():
    rule = MailRule(
        id="known-sender",
        enabled=True,
        source_folders=("Spam",),
        action=MessageAction(_settings().spam.actions.not_spam.action),
        match=RuleMatch(from_address="sender@example.org"),
    )
    service = AnalysisService(
        _settings(),
        RuleSet((rule,)),
        classifier_factory=lambda **kwargs: (_ for _ in ()).throw(AssertionError("classifier must not run")),
    )

    result = service.analyze("Spam", _message())

    assert result.decision_source == "rule"
    assert result.rule_id == "known-sender"
    assert result.configured_action == rule.action
    assert result.evidence is not None


def test_analysis_service_returns_semantic_decision_and_signals():
    class Classifier:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def assess(self, message):
            return SpamAssessment(
                signals=SemanticSpamSignals(0.1, 0.1, 0.1, 0.1, 0.1),
                evidence=build_message_evidence(message),
                model="fake-model",
                request_id="req-1",
            )

    service = AnalysisService(_settings(), RuleSet(), classifier_factory=Classifier)

    result = service.analyze("Spam", _message())

    assert result.decision_source == "semantic"
    assert result.verdict is SpamVerdict.REVIEW
    assert result.outcome is SpamOutcome.REVIEW
    assert result.model == "fake-model"
    assert result.request_id == "req-1"


def test_mail_service_lists_pages_and_opens_message_read_only(monkeypatch):
    summary = MailSummary(7, "sender", "subject", "date", "id", 123, frozenset(), None)
    message = _message()

    class FakeBrowserMailbox:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.uidvalidity = 42
            self.message_count = 2

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def fetch_summary_page(self, *, offset, limit, sort):
            assert (offset, limit, sort) == (0, 1, MessageSort.NEWEST)
            return (summary,)

        def fetch_uid(self, uid):
            return (
                MailboxItem(uid, message=message),
                PersistedState(SpamOutcome.REVIEW, frozenset({"imapledger-v1-review"})),
            )

        def search_keyword(self, keyword):
            return (7,)

    monkeypatch.setattr("imapledger.mail_service.BrowserMailbox", FakeBrowserMailbox)
    service = MailService(_settings(), "secret")

    page = service.list_messages("Other", limit=1)
    detail = service.get_message("Other", 7)

    assert page.folder == "Other"
    assert page.total == 2
    assert page.items == (summary,)
    assert page.has_next
    assert detail.item.message == message
    assert detail.persisted_state.outcome is SpamOutcome.REVIEW
