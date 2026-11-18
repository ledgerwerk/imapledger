from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console
from typer.testing import CliRunner

from imapledger import cli
from imapledger.classifier import SemanticSpamSignals
from imapledger.cleaner import CleanReport, MessageResult
from imapledger.config import ImapSettings, Settings, SpamSettings
from imapledger.mailbox import (
    ImapOperationError,
    MessageSelection,
    MessageSort,
    PartialDeleteError,
    ScopedMailbox,
)
from imapledger.policy import SpamVerdict


class FailingMailbox:
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        try:
            raise RuntimeError("password=secret raw_message=From: private@example.org")
        except RuntimeError as exc:
            raise ImapOperationError(
                operation="imap_login",
                message="IMAP login failed",
                cause_type=type(exc).__name__,
            ) from exc

    def __exit__(self, exc_type, exc, traceback):
        return None


def test_clean_debug_error_is_phase_aware_and_hides_exception_payload(monkeypatch):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folder="Spam"),
    )
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")
    monkeypatch.setattr(cli, "ScopedMailbox", FailingMailbox)

    result = CliRunner().invoke(cli.app, ["clean", "--debug"])

    assert result.exit_code == 1
    assert "error [imap_login]" in result.output
    assert "server_error_type=RuntimeError" in result.output
    assert "hint: run imapledger doctor --verbose" in result.output
    assert "Traceback (most recent call last)" in result.output
    assert "Caused by: RuntimeError" in result.output
    assert "password=secret" not in result.output
    assert "private@example.org" not in result.output


def test_clean_help_exposes_verbose_and_debug_options():
    result = CliRunner().invoke(cli.app, ["clean", "--help"])

    assert result.exit_code == 0
    assert "--verbose" in result.output
    assert "--debug" in result.output
    assert "--limit" in result.output
    assert "--offset" in result.output
    assert "--sort" in result.output
    assert "--progress" in result.output
    assert "--no-progress" in result.output


class CleanFakeMailbox:
    folder = "Spam"
    uids = frozenset({10, 20, 30, 40})

    def __init__(self):
        self.selection = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def snapshot(self):
        return self

    def selected_count(self, selection):
        self.selection = selection
        ordered = sorted(self.uids, reverse=selection.sort is MessageSort.NEWEST)
        selected = ordered[selection.offset :]
        if selection.limit is not None:
            selected = selected[: selection.limit]
        return len(selected)


class CleanFakeClassifier:
    def __init__(self, **kwargs):
        self.options = kwargs

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def _configure_clean(monkeypatch, report, output):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folder="Spam"),
    )
    mailbox = CleanFakeMailbox()
    observed = {}
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")
    monkeypatch.setattr(cli, "ScopedMailbox", lambda **kwargs: mailbox)
    monkeypatch.setattr(cli, "PyJevSpamClassifier", CleanFakeClassifier)

    class FakeCleaner:
        def __init__(self, mailbox, classifier, *, policy):
            pass

        def run(self, *, apply, selection, on_result):
            observed["apply"] = apply
            observed["selection"] = selection
            observed["on_result"] = on_result
            if on_result is not None:
                for position, row in enumerate(report.results, start=1):
                    on_result(row, position, len(report.results))
            return report

    monkeypatch.setattr(cli, "SpamCleaner", FakeCleaner)
    return mailbox, observed


def _stream_report(*, apply=False):
    return CleanReport(
        folder="Spam",
        apply=apply,
        results=[
            MessageResult(
                uid=40,
                subject="spam-subject https://tracking.example/path?token=secret",
                sender="spam@example.org",
                verdict=SpamVerdict.DELETE,
                signals=SemanticSpamSignals(0.97, 0.02, 0.15, 0.01, 0.99),
                reasons=("unsolicited-bulk", "delete-safe-corroboration"),
                status="delete",
                inclination="DELETE-APPROVED",
                deleted=apply,
            ),
            MessageResult(
                uid=30,
                subject="keep-subject",
                sender="keep@example.org",
                verdict=SpamVerdict.KEEP,
                signals=SemanticSpamSignals(0.02, 0.01, 0.03, 0.92, 0.05),
                reasons=("strong-legitimate-or-expected",),
                status="keep",
                inclination="KEEP",
            ),
            MessageResult(
                uid=20,
                subject="",
                sender="",
                verdict=None,
                signals=None,
                reasons=(),
                status="skip",
                inclination="SKIP",
                detail="message too large",
            ),
            MessageResult(
                uid=10,
                subject="error-subject",
                sender="error@example.org",
                verdict=None,
                signals=None,
                reasons=(),
                status="error",
                inclination="ERROR / KEEP",
                detail="RuntimeError: classification evaluation failed",
            ),
        ],
    )


def test_clean_forwards_selection_arguments(monkeypatch):
    output = StringIO()
    report = CleanReport(folder="Spam", apply=False, results=[])
    mailbox, observed = _configure_clean(monkeypatch, report, output)

    result = CliRunner().invoke(
        cli.app,
        ["clean", "--limit", "10", "--offset", "10", "--sort", "newest"],
    )

    expected = MessageSelection(limit=10, offset=10, sort=MessageSort.NEWEST)
    assert result.exit_code == 0
    assert observed["selection"] == expected
    assert observed["selection"] is mailbox.selection
    assert "messages=4 selected=0 sort=newest offset=10 limit=10" in output.getvalue()


@pytest.mark.parametrize(
    "arguments",
    [["clean", "--limit", "0"], ["clean", "--offset", "-1"], ["clean", "--sort", "invalid"]],
)
def test_clean_rejects_invalid_selection_options(arguments):
    result = CliRunner().invoke(cli.app, arguments)

    assert result.exit_code != 0


def test_clean_streams_decisions_once_with_summary(monkeypatch):
    output = StringIO()
    report = _stream_report()
    _configure_clean(monkeypatch, report, output)

    result = CliRunner().invoke(cli.app, ["clean"])

    rendered = output.getvalue()
    assert result.exit_code == 0
    assert "folder=Spam messages=4 selected=4 sort=newest offset=0 limit=all" in rendered
    assert "[1/4] UID 40  WOULD DELETE  Verdict=DELETE" in rendered
    assert "Signals=bulk=0.97 phishing=0.02 identity=0.15 legit=0.01 delete=0.99" in rendered
    assert "Reasons=unsolicited-bulk,delete-safe-corroboration" in rendered
    assert "[2/4] UID 30  KEEP  Verdict=KEEP" in rendered
    assert "[3/4] UID 20  SKIP / KEEP  Verdict=-  Signals=-" in rendered
    assert "[4/4] UID 10  ERROR / KEEP  Verdict=-  Signals=-" in rendered
    assert rendered.count("spam-subject") == 1
    assert "token=secret" not in rendered
    assert "/path" not in rendered
    assert "Scanned 4; delete 1; kept 1; review 0; skipped 1; errors 1; deleted 0." in rendered
    assert "Dry-run only." in rendered


def test_no_progress_suppresses_stream_and_renders_final_report(monkeypatch):
    output = StringIO()
    report = _stream_report()
    _configure_clean(monkeypatch, report, output)

    result = CliRunner().invoke(cli.app, ["clean", "--no-progress"])

    rendered = output.getvalue()
    assert result.exit_code == 0
    assert "[1/4]" not in rendered
    assert "spam-subject" in rendered
    assert "WOULD DELETE" in rendered
    assert rendered.count("spam-subject") == 1


def test_apply_progress_uses_approval_wording_not_deletion_claim(monkeypatch):
    output = StringIO()
    report = _stream_report(apply=True)
    _configure_clean(monkeypatch, report, output)

    result = CliRunner().invoke(cli.app, ["clean", "--apply"])

    rendered = output.getvalue()
    assert result.exit_code == 0
    assert "[1/4] UID 40  DELETE-APPROVED" in rendered
    assert "[1/4] UID 40  DELETED" not in rendered
    assert "Deletion: 1 approved; 1 confirmed deleted." in rendered


class DoctorFakeClient:
    def __init__(self, *, size=1, uids=(10,), fail_on=None):
        self.size = size
        self.uids = list(uids)
        self.fail_on = fail_on
        self.selected = []
        self.fetches = []
        self.added = []
        self.removed = []
        self.expunged = []
        self.logged_out = False

    def login(self, username, password):
        pass

    def logout(self):
        self.logged_out = True
        if self.fail_on == "logout":
            raise RuntimeError("password=secret logout failed")

    def capabilities(self):
        return (b"IMAP4rev1", b"UIDPLUS")

    def select_folder(self, folder, readonly=False):
        self.selected.append((folder, readonly))
        return {b"UIDVALIDITY": 42}

    def search(self, criteria="ALL", charset=None):
        return self.uids

    def fetch(self, messages, data, modifiers=None):
        messages = tuple(messages)
        data = tuple(data)
        self.fetches.append((messages, data))
        if data == ("RFC822.SIZE",):
            if self.fail_on == "size":
                raise RuntimeError("password=secret size probe failed")
            return {uid: {b"RFC822.SIZE": self.size} for uid in messages}
        if self.fail_on == "body":
            raise RuntimeError("password=secret body=DO_NOT_PRINT")
        return {uid: {b"BODY[]": b"PRIVATE BODY CONTENT"} for uid in messages}

    def add_flags(self, messages, flags, silent=False):
        self.added.append(tuple(messages))

    def remove_flags(self, messages, flags, silent=False):
        self.removed.append(tuple(messages))

    def uid_expunge(self, messages):
        self.expunged.append(tuple(messages))


def _configure_doctor(monkeypatch, client):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folder="Spam"),
    )
    factory_options = {}
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")

    def mailbox_factory(**kwargs):
        return ScopedMailbox(
            **kwargs,
            client_factory=lambda *args, **options: factory_options.update(options) or client,
        )

    monkeypatch.setattr(cli, "ScopedMailbox", mailbox_factory)
    monkeypatch.setattr(cli, "PyJevSpamClassifier", lambda: pytest.fail("doctor constructed classifier"))
    return factory_options


def test_doctor_is_read_only_and_discards_body(monkeypatch):
    client = DoctorFakeClient()
    factory_options = _configure_doctor(monkeypatch, client)

    result = CliRunner().invoke(cli.app, ["doctor", "--verbose"])

    assert result.exit_code == 0
    assert "TLS connect: OK" in result.output
    assert "login: OK" in result.output
    assert "UIDVALIDITY: 42" in result.output
    assert "FETCH RFC822.SIZE (1 UID): OK" in result.output
    assert "FETCH BODY.PEEK[] (1 UID): OK" in result.output
    assert "PRIVATE BODY CONTENT" not in result.output
    assert client.selected == [("Spam", True)]
    assert client.fetches == [((10,), ("RFC822.SIZE",)), ((10,), ("BODY.PEEK[]",))]
    assert client.added == client.removed == client.expunged == []
    assert client.logged_out
    assert factory_options["use_uid"] is True


def test_doctor_size_probe_failure_is_contextual_and_private(monkeypatch):
    client = DoctorFakeClient(fail_on="size")
    _configure_doctor(monkeypatch, client)

    result = CliRunner().invoke(cli.app, ["doctor"])

    assert result.exit_code == 1
    assert "error [imap_fetch_size]" in result.output
    assert "selector=RFC822.SIZE" in result.output
    assert "password=secret" not in result.output
    assert "PRIVATE BODY CONTENT" not in result.output


def test_doctor_body_probe_failure_is_contextual_and_private(monkeypatch):
    client = DoctorFakeClient(fail_on="body")
    _configure_doctor(monkeypatch, client)

    result = CliRunner().invoke(cli.app, ["doctor"])

    assert result.exit_code == 1
    assert "error [imap_fetch_body]" in result.output
    assert "uid=10" in result.output
    assert "password=secret" not in result.output
    assert "DO_NOT_PRINT" not in result.output


def test_doctor_skips_body_probe_when_message_exceeds_size_limit(monkeypatch):
    client = DoctorFakeClient(size=2_000_001)
    _configure_doctor(monkeypatch, client)

    result = CliRunner().invoke(cli.app, ["doctor"])

    assert result.exit_code == 0
    assert "FETCH RFC822.SIZE (1 UID): OK" in result.output
    assert "FETCH BODY.PEEK[]: SKIPPED" in result.output
    assert [selector for _, selector in client.fetches] == [("RFC822.SIZE",)]


def test_doctor_logout_failure_is_contextual_and_private(monkeypatch):
    client = DoctorFakeClient(fail_on="logout")
    _configure_doctor(monkeypatch, client)

    result = CliRunner().invoke(cli.app, ["doctor"])

    assert result.exit_code == 1
    assert "error [imap_logout]" in result.output
    assert "password=secret" not in result.output


def test_report_shows_verdict_signals_reasons_and_safe_skip_error_detail(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    report = CleanReport(
        folder="Spam",
        apply=False,
        results=[
            MessageResult(
                uid=1,
                subject="spam https://tracking.example/path?token=secret",
                sender="a@example.org",
                verdict=SpamVerdict.DELETE,
                signals=SemanticSpamSignals(0.97, 0.1, 0.2, 0.03, 0.91),
                reasons=("unsolicited-bulk",),
                status="delete",
                inclination="DELETE-APPROVED",
            ),
            MessageResult(
                uid=2,
                subject="",
                sender="",
                verdict=None,
                signals=None,
                reasons=(),
                status="skip",
                inclination="SKIP",
                detail="message exceeds size limit",
            ),
            MessageResult(
                uid=3,
                subject="real",
                sender="b@example.org",
                verdict=None,
                signals=None,
                reasons=(),
                status="error",
                inclination="ERROR / KEEP",
                detail="RuntimeError: classification evaluation failed",
            ),
            MessageResult(
                uid=4,
                subject="maybe",
                sender="c@example.org",
                verdict=SpamVerdict.REVIEW,
                signals=SemanticSpamSignals(0.2, 0.2, 0.1, 0.1, 0.99),
                reasons=("insufficient-evidence",),
                status="review",
                inclination="REVIEW / KEEP",
            ),
        ],
    )

    cli._print_report(report)

    rendered = output.getvalue()
    assert "Verdict" in rendered
    assert "Signals" in rendered
    assert "Reasons" in rendered
    assert "WOULD DELETE" in rendered
    assert "REVIEW / KEEP" in rendered
    assert "ERROR / KEEP" in rendered
    assert "message exceeds size limit" in rendered
    assert "tracking.example" in rendered
    assert "token=secret" not in rendered
    assert "/path" not in rendered


def test_partial_delete_report_distinguishes_confirmed_and_pending_uids(monkeypatch):
    failure = ImapOperationError(
        operation="imap_uid_expunge",
        message="UID EXPUNGE failed",
        folder="Spam",
        uids=(2,),
        batch=2,
        batch_count=2,
        cause_type="RuntimeError",
    )
    partial = PartialDeleteError(deleted=(1,), pending=(2,), failure=failure)
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    signals = SemanticSpamSignals(0.1, 0.99, 0.1, 0.1, 0.9)
    report = CleanReport(
        folder="Spam",
        apply=True,
        partial_delete_error=partial,
        results=[
            MessageResult(
                uid=1,
                subject="confirmed",
                sender="a@example.org",
                verdict=SpamVerdict.DELETE,
                signals=signals,
                reasons=("phishing",),
                status="delete",
                inclination="DELETE-APPROVED",
                deleted=True,
            ),
            MessageResult(
                uid=2,
                subject="pending",
                sender="b@example.org",
                verdict=SpamVerdict.DELETE,
                signals=signals,
                reasons=("phishing",),
                status="delete",
                inclination="DELETE-APPROVED",
                detail="Deletion was not confirmed; see the operation error.",
            ),
        ],
    )

    cli._print_report(report)

    rendered = output.getvalue()
    assert "DELETED" in rendered
    assert "NOT CONFIRMED" in rendered
    assert "Partial deletion: 1 confirmed; 1 pending." in rendered


def test_clean_exits_nonzero_after_partial_delete(monkeypatch):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folder="Spam"),
    )
    failure = ImapOperationError(
        operation="imap_uid_expunge",
        message="deletion stopped after a failed UID batch",
        folder="Spam",
        uids=(2,),
        batch=2,
        batch_count=2,
        cause_type="RuntimeError",
    )
    partial = PartialDeleteError(deleted=(1,), pending=(2,), failure=failure)
    signals = SemanticSpamSignals(0.1, 0.99, 0.1, 0.1, 0.9)
    report = CleanReport(
        folder="Spam",
        apply=True,
        partial_delete_error=partial,
        results=[
            MessageResult(
                uid=1,
                subject="confirmed",
                sender="a@example.org",
                verdict=SpamVerdict.DELETE,
                signals=signals,
                reasons=("phishing",),
                status="delete",
                inclination="DELETE-APPROVED",
                deleted=True,
            ),
            MessageResult(
                uid=2,
                subject="pending",
                sender="b@example.org",
                verdict=SpamVerdict.DELETE,
                signals=signals,
                reasons=("phishing",),
                status="delete",
                inclination="DELETE-APPROVED",
            ),
        ],
    )

    class Context:
        folder = "Spam"
        uids = frozenset({1, 2})

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def snapshot(self):
            return self

        def selected_count(self, selection):
            return len(self.uids)

    class FakeCleaner:
        def __init__(self, mailbox, classifier, *, policy):
            pass

        def run(self, *, apply, selection, on_result):
            if on_result is not None:
                for position, row in enumerate(report.results, start=1):
                    on_result(row, position, len(report.results))
            return report

    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")
    monkeypatch.setattr(cli, "ScopedMailbox", lambda **kwargs: Context())
    monkeypatch.setattr(cli, "PyJevSpamClassifier", CleanFakeClassifier)
    monkeypatch.setattr(cli, "SpamCleaner", FakeCleaner)

    result = CliRunner().invoke(cli.app, ["clean", "--apply"])

    assert result.exit_code == 1
    assert "NOT CONFIRMED" in output.getvalue()
    assert "confirmed_deleted_count=1 pending_count=1" in result.output
    assert "hint: run imapledger doctor --verbose" in result.output
