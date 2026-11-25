from __future__ import annotations

from typer.testing import CliRunner

from imapledger import cli
from imapledger.action_service import ActionReceipt
from imapledger.analysis_service import MessageAnalysis
from imapledger.classification_state import SpamOutcome
from imapledger.config import ImapSettings, Settings, SpamSettings
from imapledger.mail_service import MessageDetail, MessagePage
from imapledger.mailbox import MailboxItem, MessageSort
from imapledger.message import MailSummary, parse_message
from imapledger.policy import SpamVerdict
from imapledger.rules import RuleSet

SETTINGS = Settings(
    imap=ImapSettings(host="imap.example.org", username="user@example.org"),
    spam=SpamSettings(folders=("Spam",)),
)
MESSAGE = parse_message(9, b"From: sender@example.org\r\nSubject: Hello\r\n\r\nSafe body", max_body_chars=100)
SUMMARY = MailSummary(9, MESSAGE.sender, MESSAGE.subject, MESSAGE.date, MESSAGE.message_id, 100, frozenset(), None)
PAGE = MessagePage("Spam", 42, 0, 50, MessageSort.NEWEST, 1, (SUMMARY,), False, False)
DETAIL = MessageDetail("Spam", 42, MailboxItem(9, message=MESSAGE), None)


class FakeMailService:
    instances = []

    def __init__(self, settings, password):
        self.closed = False
        self.instances.append(self)

    def list_messages(self, folder, **kwargs):
        return PAGE

    def get_message(self, folder, uid):
        return DETAIL

    def close(self):
        self.closed = True


def _setup(monkeypatch):
    FakeMailService.instances.clear()
    monkeypatch.setattr(cli, "_load_auth_settings", lambda config: SETTINGS)
    monkeypatch.setattr(cli, "_resolve_password", lambda imap: "secret")
    monkeypatch.setattr(cli, "MailService", FakeMailService)
    monkeypatch.setattr(cli, "load_rules", lambda *args, **kwargs: RuleSet())


def test_mail_list_renders_page_headers(monkeypatch):
    _setup(monkeypatch)

    result = CliRunner().invoke(cli.app, ["mail", "list", "--folder", "Spam"])

    assert result.exit_code == 0
    assert "Hello" in result.output
    assert "sender@example.org" in result.output
    assert "Safe body" not in result.output
    assert FakeMailService.instances[0].closed


def test_mail_show_displays_bounded_plain_text_message(monkeypatch):
    _setup(monkeypatch)

    result = CliRunner().invoke(cli.app, ["mail", "show", "9", "--folder", "Spam"])

    assert result.exit_code == 0
    assert "Subject: Hello" in result.output
    assert "Safe body" in result.output
    assert "Body source: plain" in result.output


def test_mail_classify_is_preview_only_without_apply(monkeypatch):
    _setup(monkeypatch)

    class FakeAnalysisService:
        def __init__(self, settings, rules, *, classifier_factory):
            pass

        def analyze(self, folder, message, **kwargs):
            assert kwargs["use_routing_filters"] is False
            return MessageAnalysis(
                folder,
                message.uid,
                None,
                None,
                SpamOutcome.REVIEW,
                SpamVerdict.REVIEW,
                None,
                ("needs-review",),
                SETTINGS.spam.actions.review,
                decision_source="semantic",
            )

    monkeypatch.setattr(cli, "AnalysisService", FakeAnalysisService)
    result = CliRunner().invoke(cli.app, ["mail", "classify", "9", "--folder", "Spam"])

    assert result.exit_code == 0
    assert "Result: Not applied (preview)" in result.output


def test_mail_classify_apply_reports_confirmed_action(monkeypatch):
    _setup(monkeypatch)

    class FakeAnalysisService:
        def __init__(self, settings, rules, *, classifier_factory):
            pass

        def analyze(self, folder, message, **kwargs):
            assert kwargs["use_routing_filters"] is False
            return MessageAnalysis(
                folder,
                message.uid,
                None,
                None,
                SpamOutcome.REVIEW,
                SpamVerdict.REVIEW,
                None,
                (),
                SETTINGS.spam.actions.review,
                decision_source="semantic",
            )

    class FakeActionService:
        def __init__(self, settings, password):
            pass

        def apply(self, analysis, *, uidvalidity, confirmed_by_user):
            assert analysis.folder == "INBOX"
            assert uidvalidity == 42
            assert confirmed_by_user
            return ActionReceipt(
                analysis.folder,
                uidvalidity,
                analysis.uid,
                analysis.configured_action,
                None,
                analysis.decision_source,
                True,
                True,
            )

    monkeypatch.setattr(cli, "AnalysisService", FakeAnalysisService)
    monkeypatch.setattr(cli, "ActionService", FakeActionService)
    result = CliRunner().invoke(cli.app, ["mail", "classify", "9", "--folder", "INBOX", "--apply"])

    assert result.exit_code == 0
    assert "Result: Applied and confirmed" in result.output


def test_mail_classify_help_describes_global_action_scope():
    result = CliRunner().invoke(cli.app, ["mail", "classify", "--help"])

    assert result.exit_code == 0
    assert "selectable mailbox folder" in result.output
    assert "category's configured action" in result.output


def test_ui_is_explicit_and_root_no_args_prints_help():
    runner = CliRunner()
    no_args = runner.invoke(cli.app, [])
    ui_help = runner.invoke(cli.app, ["ui", "--help"])

    assert no_args.exit_code == 2
    assert "Usage:" in no_args.output
    assert ui_help.exit_code == 0
    assert "interactive terminal mail review console" in ui_help.output
