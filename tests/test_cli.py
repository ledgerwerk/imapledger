from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console
from typer.testing import CliRunner

from imapledger import cli
from imapledger.classifier import SemanticSpamSignals
from imapledger.cleaner import CleanReport, MessageResult, SpamOutcome
from imapledger.config import (
    ActionKind,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    load_settings,
)
from imapledger.mailbox import (
    FolderInfo,
    ImapOperationError,
    MailboxProbe,
    MessageSelection,
    MessageSort,
    PartialDeleteError,
    PartialMoveError,
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
        spam=SpamSettings(folders=("Spam",)),
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
    capabilities = frozenset({b"MOVE", b"UIDPLUS"})
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

    def destination_exists(self, destination):
        return True


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
        spam=SpamSettings(folders=("Spam",)),
    )
    mailbox = CleanFakeMailbox()
    observed = {}
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")
    monkeypatch.setattr(cli, "ScopedMailbox", lambda **kwargs: mailbox)
    monkeypatch.setattr(cli, "PyJevSpamClassifier", CleanFakeClassifier)

    class FakeCleaner:
        def __init__(self, mailbox, classifier, *, policy, actions=None):
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
                action=MessageAction(ActionKind.DELETE),
                outcome=SpamOutcome.SPAM,
                action_applied=apply,
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
                outcome=SpamOutcome.NOT_SPAM,
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
    assert "[1/4] UID 40  WOULD DELETE  Outcome=SPAM  Verdict=DELETE" in rendered
    assert "Signals=bulk=0.97 phishing=0.02 identity=0.15 legit=0.01 delete=0.99" in rendered
    assert "Reasons=unsolicited-bulk,delete-safe-corroboration" in rendered
    assert "[2/4] UID 30  KEEP  Outcome=NOT_SPAM  Verdict=KEEP" in rendered
    assert "[3/4] UID 20  SKIP / KEEP  Outcome=-  Verdict=-  Signals=-" in rendered
    assert "[4/4] UID 10  ERROR / KEEP  Outcome=-  Verdict=-  Signals=-" in rendered
    assert rendered.count("spam-subject") == 1
    assert "token=secret" not in rendered
    assert "/path" not in rendered
    assert "Scanned 4; spam 1; not-spam 1; review 0; skipped 1; errors 1." in rendered
    assert "Actions: would delete 1; kept 3." in rendered
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
    assert "folder=Spam UID 40  DELETED" in rendered
    assert "Actions: deleted 1; kept 3." in rendered


class DoctorFakeClient:
    def __init__(self, *, size=1, uids=(10,), fail_on=None, existing_folders=("Spam",)):
        self.size = size
        self.uids = list(uids)
        self.fail_on = fail_on
        self.selected = []
        self.fetches = []
        self.added = []
        self.removed = []
        self.expunged = []
        self.logged_out = False
        self.existing_folders = set(existing_folders)
        self.folder_queries = []

    def login(self, username, password):
        pass

    def logout(self):
        self.logged_out = True
        if self.fail_on == "logout":
            raise RuntimeError("password=secret logout failed")

    def capabilities(self):
        return (b"IMAP4rev1", b"UIDPLUS")

    def folder_exists(self, folder):
        self.folder_queries.append(folder)
        return folder in self.existing_folders

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


def _configure_doctor(monkeypatch, client, settings=None):
    if settings is None:
        settings = Settings(
            imap=ImapSettings(host="imap.example.org", username="user@example.org"),
            spam=SpamSettings(folders=("Spam",)),
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
    assert "source: EXISTS" in result.output
    assert "select: OK" in result.output
    assert "UIDVALIDITY: 42" in result.output
    assert "FETCH RFC822.SIZE (1 UID): OK" in result.output
    assert "FETCH BODY.PEEK[] (1 UID): OK" in result.output
    assert "PRIVATE BODY CONTENT" not in result.output
    assert client.selected == [("Spam", True)]
    assert client.fetches == [((10,), ("RFC822.SIZE",)), ((10,), ("BODY.PEEK[]",))]
    assert client.added == client.removed == client.expunged == []
    assert client.logged_out
    assert factory_options["use_uid"] is True


def test_doctor_reports_missing_source_and_checks_later_sources(monkeypatch):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("INBOX.Junk", "INBOX.Spam", "INBOX.Later")),
    )
    client = DoctorFakeClient(existing_folders=("INBOX.Junk", "INBOX.Later"))
    prompts = []
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    _configure_doctor(monkeypatch, client, settings=settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "secret")

    result = CliRunner().invoke(cli.app, ["doctor", "--verbose"])

    assert result.exit_code == 1
    assert len(prompts) == 1
    assert client.folder_queries == ["INBOX.Junk", "INBOX.Spam", "INBOX.Later"]
    assert client.selected == [("INBOX.Junk", True), ("INBOX.Later", True)]
    assert "source: MISSING" in output.getvalue()
    assert "error [imap_source_folder_missing]" in result.output
    assert "folder='INBOX.Spam'" in result.output
    assert "folder: INBOX.Later (read-only)" in output.getvalue()
    assert "hint: run imapledger doctor --verbose" not in result.output
    assert "Traceback" not in result.output


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
                action=MessageAction(ActionKind.DELETE),
                outcome=SpamOutcome.SPAM,
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
                outcome=SpamOutcome.REVIEW,
            ),
        ],
    )

    cli._print_report(report)

    rendered = output.getvalue()
    assert "Verdict" in rendered
    assert "Signals" in rendered
    assert "Reasons" in rendered
    assert "WOULD DELETE" in rendered
    assert "Outcome" in rendered and "REVIEW" in rendered
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
                action=MessageAction(ActionKind.DELETE),
                outcome=SpamOutcome.SPAM,
                action_applied=True,
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
                action=MessageAction(ActionKind.DELETE),
                outcome=SpamOutcome.SPAM,
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
        spam=SpamSettings(folders=("Spam",)),
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
                action=MessageAction(ActionKind.DELETE),
                outcome=SpamOutcome.SPAM,
                action_applied=True,
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
                action=MessageAction(ActionKind.DELETE),
                outcome=SpamOutcome.SPAM,
            ),
        ],
    )

    class Context:
        folder = "Spam"
        uids = frozenset({1, 2})
        capabilities = frozenset({b"MOVE", b"UIDPLUS"})

        def destination_exists(self, destination):
            return True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def snapshot(self):
            return self

        def selected_count(self, selection):
            return len(self.uids)

    class FakeCleaner:
        def __init__(self, mailbox, classifier, *, policy, actions=None):
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


def test_config_show_prints_effective_config_without_prompt_or_connection(monkeypatch, tmp_path):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(
            folders=("INBOX.Junk", "INBOX.Spam"),
            actions=SpamActions(spam=MessageAction(ActionKind.MOVE, "INBOX.Trash")),
        ),
    )
    output = StringIO()
    config_path = tmp_path / "config.toml"
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("config show prompted"))
    monkeypatch.setattr(cli, "ScopedMailbox", lambda **kwargs: pytest.fail("config show connected"))

    result = CliRunner().invoke(cli.app, ["config", "show", "--config", str(config_path)])

    rendered = output.getvalue()
    assert result.exit_code == 0
    assert f"config: {config_path}" in rendered
    assert 'folders = ["INBOX.Junk", "INBOX.Spam"]' in rendered
    assert "[spam.actions.spam]" in rendered
    assert 'destination = "INBOX.Trash"' in rendered
    assert "password" not in rendered.lower()


def test_init_writes_repeated_folders_and_configured_actions(monkeypatch, tmp_path):
    output = StringIO()
    config_path = tmp_path / "config.toml"
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))

    result = CliRunner().invoke(
        cli.app,
        [
            "init",
            "--host",
            "imap.example.org",
            "--username",
            "me@example.org",
            "--folder",
            "INBOX.Junk",
            "--folder",
            "INBOX.Spam",
            "--spam-action",
            "move",
            "--spam-destination",
            "INBOX.Trash",
            "--not-spam-action",
            "move",
            "--not-spam-destination",
            "INBOX.NotSpam",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0, result.output
    settings = load_settings(config_path)
    assert settings.spam.folders == ("INBOX.Junk", "INBOX.Spam")
    assert settings.spam.actions.spam == MessageAction(ActionKind.MOVE, "INBOX.Trash")
    assert settings.spam.actions.not_spam == MessageAction(ActionKind.MOVE, "INBOX.NotSpam")
    assert "password" not in config_path.read_text(encoding="utf-8").lower()


def _install_multi_clean(
    monkeypatch,
    settings,
    output,
    *,
    report_factory=None,
    destination_exists=True,
    preflight_failure_folder=None,
):
    state = {
        "prompts": [],
        "classifier_instances": [],
        "classifier_contexts": [],
        "mailboxes": [],
        "clean_calls": [],
        "events": [],
    }
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: state["prompts"].append(prompt) or "secret")

    class FakeMailbox:
        def __init__(self, **kwargs):
            self.folder = kwargs["folder"]
            self.kwargs = kwargs
            self.uids = frozenset(range(1, 31))
            self.capabilities = frozenset({b"MOVE", b"UIDPLUS"})
            self.selections = []
            state["mailboxes"].append(self)
            state["events"].append(("open", self.folder))

        def __enter__(self):
            if self.folder == preflight_failure_folder and not self.kwargs["writable"]:
                raise ImapOperationError(
                    operation="imap_source_folder_missing",
                    message="configured source folder does not exist",
                    folder=self.folder,
                )
            return self

        def __exit__(self, *args):
            state["events"].append(("close", self.folder))

        def snapshot(self):
            return self

        def selected_count(self, selection):
            self.selections.append(selection)
            ordered = sorted(self.uids, reverse=selection.sort is MessageSort.NEWEST)
            selected = ordered[selection.offset :]
            if selection.limit is not None:
                selected = selected[: selection.limit]
            return len(selected)

        def destination_exists(self, destination):
            state["events"].append(("destination", self.folder, destination))
            return destination_exists

    monkeypatch.setattr(cli, "ScopedMailbox", FakeMailbox)

    class CountingClassifier:
        def __init__(self, **kwargs):
            self.options = kwargs
            state["classifier_instances"].append(self)

        def __enter__(self):
            state["classifier_contexts"].append(self)
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(cli, "PyJevSpamClassifier", CountingClassifier)

    class FakeCleaner:
        def __init__(self, mailbox, classifier, *, policy, actions):
            self.mailbox = mailbox
            self.classifier = classifier
            self.actions = actions

        def run(self, *, apply, selection, on_result):
            state["clean_calls"].append((self.mailbox.folder, self.classifier, selection))
            state["events"].append(("classify", self.mailbox.folder))
            report = (
                report_factory(self.mailbox, apply)
                if report_factory
                else CleanReport(
                    folder=self.mailbox.folder,
                    apply=apply,
                    results=[
                        MessageResult(
                            uid=10,
                            subject="spam",
                            sender="spam@example.org",
                            verdict=SpamVerdict.DELETE,
                            signals=SemanticSpamSignals(0.1, 0.99, 0.1, 0.1, 0.9),
                            reasons=("phishing",),
                            status="delete",
                            inclination="DELETE-APPROVED",
                            action=self.actions.spam,
                            outcome=SpamOutcome.SPAM,
                            action_applied=apply,
                        )
                    ],
                )
            )
            if on_result is not None:
                for position, row in enumerate(report.results, start=1):
                    on_result(row, position, len(report.results))
            return report

    monkeypatch.setattr(cli, "SpamCleaner", FakeCleaner)
    return state


def _multi_folder_settings(folders=("INBOX.Junk", "INBOX.Spam")):
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(
            folders=folders,
            actions=SpamActions(
                spam=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
                not_spam=MessageAction(ActionKind.MOVE, "INBOX.NotSpam"),
            ),
        ),
    )


def test_clean_visits_multiple_folders_in_order_with_one_password_and_classifier(monkeypatch):
    output = StringIO()
    settings = _multi_folder_settings()
    state = _install_multi_clean(monkeypatch, settings, output)

    result = CliRunner().invoke(
        cli.app,
        ["clean", "--limit", "10", "--offset", "10", "--sort", "newest"],
    )

    selection = MessageSelection(limit=10, offset=10, sort=MessageSort.NEWEST)
    rendered = output.getvalue()
    assert result.exit_code == 0
    assert len(state["prompts"]) == 1
    assert len(state["classifier_instances"]) == len(state["classifier_contexts"]) == 1
    assert [folder for folder, _, _ in state["clean_calls"]] == ["INBOX.Junk", "INBOX.Spam"]
    assert all(classifier is state["classifier_instances"][0] for _, classifier, _ in state["clean_calls"])
    assert all(actual == selection for _, _, actual in state["clean_calls"])
    assert state["clean_calls"][0][2] is state["clean_calls"][1][2]
    assert all(mailbox.selections == [selection] for mailbox in state["mailboxes"])
    assert "folder=INBOX.Junk messages=30 selected=10 sort=newest offset=10 limit=10" in rendered
    assert "folder=INBOX.Spam messages=30 selected=10 sort=newest offset=10 limit=10" in rendered
    assert rendered.count("WOULD MOVE -> INBOX.Trash") == 2
    assert "Aggregate across 2 folders (UIDs remain folder-scoped): scanned 2; spam 2;" in rendered


def test_clean_apply_preflights_each_destination_before_classifying(monkeypatch):
    output = StringIO()
    state = _install_multi_clean(monkeypatch, _multi_folder_settings(), output)

    result = CliRunner().invoke(cli.app, ["clean", "--apply"])

    rendered = output.getvalue()
    assert result.exit_code == 0
    assert len(state["prompts"]) == 1
    assert len(state["classifier_instances"]) == 1
    first_classify = next(index for index, event in enumerate(state["events"]) if event[0] == "classify")
    assert state["events"].index(("close", "INBOX.Spam")) < first_classify
    assert [mailbox.kwargs["writable"] for mailbox in state["mailboxes"]] == [False, False, True, True]
    for folder in ("INBOX.Junk", "INBOX.Spam"):
        folder_events = [event for event in state["events"] if event[1] == folder]
        assert folder_events.index(("destination", folder, "INBOX.Trash")) < folder_events.index(("classify", folder))
        assert folder_events.index(("destination", folder, "INBOX.NotSpam")) < folder_events.index(("classify", folder))
    assert rendered.count("MOVE-APPROVED -> INBOX.Trash") == 2
    assert rendered.count("MOVED -> INBOX.Trash") == 2
    assert "Aggregate across 2 folders" in rendered


def test_clean_apply_aborts_all_sources_before_classifier_or_mutation(monkeypatch):
    output = StringIO()
    state = _install_multi_clean(
        monkeypatch,
        _multi_folder_settings(),
        output,
        preflight_failure_folder="INBOX.Spam",
    )

    result = CliRunner().invoke(cli.app, ["clean", "--apply"])

    rendered = output.getvalue()
    assert result.exit_code == 1
    assert len(state["prompts"]) == 1
    assert [mailbox.folder for mailbox in state["mailboxes"]] == ["INBOX.Junk", "INBOX.Spam"]
    assert all(mailbox.kwargs["writable"] is False for mailbox in state["mailboxes"])
    assert state["classifier_instances"] == []
    assert state["clean_calls"] == []
    assert "preflight INBOX.Junk: OK" in rendered
    assert "preflight INBOX.Spam: FAILED" in rendered
    assert "error [imap_source_folder_missing]" in result.output
    assert "apply aborted before classification/mutation" in rendered
    assert "MOVED" not in rendered and "DELETED" not in rendered
    assert "Traceback" not in result.output


def test_clean_partial_move_exits_nonzero_and_keeps_confirmed_reporting(monkeypatch):
    output = StringIO()
    settings = _multi_folder_settings()
    failure = ImapOperationError(
        operation="imap_uid_move",
        message="move stopped after a failed UID batch",
        folder="INBOX.Junk",
        uids=(20,),
        batch=2,
        batch_count=2,
        cause_type="RuntimeError",
        server_status="NO",
    )
    partial = PartialMoveError(
        moved=(10,),
        pending=(20,),
        destination="INBOX.Trash",
        failure=failure,
    )

    def report_factory(mailbox, apply):
        return CleanReport(
            folder=mailbox.folder,
            apply=apply,
            partial_move_error=partial,
            results=[
                MessageResult(
                    uid=10,
                    subject="confirmed",
                    sender="a@example.org",
                    verdict=SpamVerdict.DELETE,
                    signals=SemanticSpamSignals(0.1, 0.99, 0.1, 0.1, 0.9),
                    reasons=("phishing",),
                    status="delete",
                    inclination="DELETE-APPROVED",
                    action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
                    outcome=SpamOutcome.SPAM,
                    action_applied=True,
                ),
                MessageResult(
                    uid=20,
                    subject="pending",
                    sender="b@example.org",
                    verdict=SpamVerdict.DELETE,
                    signals=SemanticSpamSignals(0.1, 0.99, 0.1, 0.1, 0.9),
                    reasons=("phishing",),
                    status="delete",
                    inclination="DELETE-APPROVED",
                    action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
                    outcome=SpamOutcome.SPAM,
                    detail="Move was not confirmed; see the operation error.",
                ),
            ],
        )

    state = _install_multi_clean(monkeypatch, settings, output, report_factory=report_factory)
    result = CliRunner().invoke(cli.app, ["clean", "--apply"])

    rendered = output.getvalue()
    assert result.exit_code == 1
    assert [(mailbox.folder, mailbox.kwargs["writable"]) for mailbox in state["mailboxes"]] == [
        ("INBOX.Junk", False),
        ("INBOX.Spam", False),
        ("INBOX.Junk", True),
    ]
    assert "folder=INBOX.Junk UID 10  MOVED -> INBOX.Trash" in rendered
    assert "folder=INBOX.Junk UID 20  MOVE NOT CONFIRMED -> INBOX.Trash" in rendered
    assert "Aggregate across 1 folders" in rendered
    assert "destination='INBOX.Trash'" in result.output


def test_doctor_checks_all_source_folders_capabilities_and_destinations(monkeypatch):
    settings = _multi_folder_settings()
    probes = []
    selections = []
    prompts = []
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "secret")
    monkeypatch.setattr(cli, "PyJevSpamClassifier", lambda **kwargs: pytest.fail("doctor constructed classifier"))

    class DoctorScope:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.folder = kwargs["folder"]
            self.capabilities = {b"MOVE"}

        def __enter__(self):
            selections.append((self.folder, self.kwargs["writable"]))
            return self

        def __exit__(self, *args):
            return None

        def probe(self):
            probes.append(self.folder)
            return MailboxProbe(42, 1, 10, 10, 10, 10, None)

        def destination_exists(self, destination):
            return destination in {"INBOX.Trash", "INBOX.NotSpam"}

    monkeypatch.setattr(cli, "ScopedMailbox", DoctorScope)

    result = CliRunner().invoke(cli.app, ["doctor"])

    rendered = output.getvalue()
    assert result.exit_code == 0
    assert len(prompts) == 1
    assert probes == ["INBOX.Junk", "INBOX.Spam"]
    assert selections == [("INBOX.Junk", False), ("INBOX.Spam", False)]
    assert rendered.count("required capability MOVE: OK") == 2
    assert rendered.count("destination INBOX.Trash: OK") == 2
    assert rendered.count("destination INBOX.NotSpam: OK") == 2
    assert "result: IMAP read/action preflight is healthy" in rendered


def test_doctor_reports_missing_preconditions_for_each_folder_and_continues(monkeypatch):
    settings = _multi_folder_settings()
    probes = []
    prompts = []
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "secret")

    class DoctorScope:
        def __init__(self, **kwargs):
            self.folder = kwargs["folder"]
            self.kwargs = kwargs
            self.capabilities = {b"MOVE"} if self.folder == "INBOX.Junk" else set()

        def __enter__(self):
            assert self.kwargs["writable"] is False
            return self

        def __exit__(self, *args):
            return None

        def probe(self):
            probes.append(self.folder)
            return MailboxProbe(42, 1, 10, 10, 10, 10, None)

        def destination_exists(self, destination):
            return not (self.folder == "INBOX.Spam" and destination == "INBOX.NotSpam")

    monkeypatch.setattr(cli, "ScopedMailbox", DoctorScope)

    result = CliRunner().invoke(cli.app, ["doctor"])

    assert result.exit_code == 1
    assert len(prompts) == 1
    assert probes == ["INBOX.Junk", "INBOX.Spam"]
    assert "required capability MOVE: MISSING" in output.getvalue()
    assert "destination INBOX.NotSpam: MISSING" in output.getvalue()
    assert "preflight has failures" in output.getvalue()


def _folder_cli_rows(status_error=None):
    return (
        FolderInfo("INBOX", ".", {b"\\INBOX", b"\\HASCHILDREN"}, 10234, 54),
        FolderInfo("INBOX.Junk", ".", {b"\\JUNK", b"\\HASNOCHILDREN"}, 36575, 5),
        FolderInfo("INBOX.Trash", ".", {b"\\TRASH", b"\\HASNOCHILDREN"}, 5030, 30),
        FolderInfo("Shared", ".", {b"\\NOSELECT", b"\\HASCHILDREN"}, None, None),
        FolderInfo("Legacy", ".", {b"\\HASNOCHILDREN"}, None, None, status_error),
    )


def _configure_folders(monkeypatch, rows, output, errors, *, fatal=None, fatal_stage="enter"):
    state = {}
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "err_console", Console(file=errors, width=200))

    class FakeCatalog:
        def __init__(self, **kwargs):
            state["kwargs"] = kwargs

        def __enter__(self):
            if fatal is not None and fatal_stage == "enter":
                raise fatal
            return self

        def __exit__(self, *args):
            return None

        def list_folders(self, *, include_counts):
            state["include_counts"] = include_counts
            if fatal is not None and fatal_stage == "list":
                raise fatal
            return rows

    monkeypatch.setattr(cli, "FolderCatalog", FakeCatalog)
    return state


def test_folders_help_describes_read_only_command_and_options():
    result = CliRunner().invoke(cli.app, ["folders", "--help"])

    assert result.exit_code == 0
    assert "without reading message contents" in result.output
    assert "mutating" in result.output
    for option in ("--config", "--host", "--username", "--port", "--counts", "--no-counts", "--verbose"):
        assert option in result.output


def test_folders_config_mode_loads_only_imap_settings_and_renders_metadata(monkeypatch, tmp_path):
    output = StringIO()
    errors = StringIO()
    config_path = tmp_path / "imap-only.toml"
    prompts = []
    settings = ImapSettings(host="imap.example.org", username="me@example.org", port=1993)
    loaded = []
    monkeypatch.setattr(cli, "load_imap_settings", lambda path: loaded.append(path) or settings)
    monkeypatch.setattr(cli, "load_settings", lambda path: pytest.fail("folders must not load spam settings"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "secret")
    state = _configure_folders(monkeypatch, _folder_cli_rows(), output, errors)

    result = CliRunner().invoke(cli.app, ["folders", "--config", str(config_path)])

    rendered = output.getvalue()
    assert result.exit_code == 0, result.output
    assert loaded == [config_path]
    assert prompts == ["IMAP password: "]
    assert state["kwargs"] == {
        "host": "imap.example.org",
        "port": 1993,
        "username": "me@example.org",
        "password": "secret",
        "event_callback": None,
    }
    assert state["include_counts"] is True
    assert "INBOX.Junk" in rendered
    assert "INBOX.Trash" in rendered
    assert "Total" in rendered and "Read" in rendered and "Unread" in rendered
    assert "Junk" in rendered and "Trash" in rendered
    assert "Shared" in rendered
    assert errors.getvalue() == ""


def test_folders_direct_mode_uses_host_user_and_default_or_requested_port(monkeypatch):
    for extra_args, expected_port in (([], 993), (["--port", "1993"], 1993)):
        output = StringIO()
        errors = StringIO()
        monkeypatch.setattr(
            cli,
            "load_imap_settings",
            lambda path: pytest.fail("direct mode must not read the configuration"),
        )
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")
        state = _configure_folders(monkeypatch, (), output, errors)

        result = CliRunner().invoke(
            cli.app,
            ["folders", "--host", "imap.example.org", "--username", "me@example.org", *extra_args],
        )

        assert result.exit_code == 0, result.output
        assert state["kwargs"]["host"] == "imap.example.org"
        assert state["kwargs"]["username"] == "me@example.org"
        assert state["kwargs"]["port"] == expected_port


@pytest.mark.parametrize(
    "arguments",
    [
        ["--host", "imap.example.org"],
        ["--username", "me@example.org"],
        ["--port", "1993"],
    ],
)
def test_folders_rejects_incomplete_direct_options(arguments, monkeypatch):
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "secret")
    monkeypatch.setattr(cli, "load_imap_settings", lambda path: pytest.fail("invalid direct mode used config"))

    result = CliRunner().invoke(cli.app, ["folders", *arguments])

    assert result.exit_code == 2
    assert "requires both --host and --username" in result.output
    assert prompts == []


def test_folders_empty_password_exits_before_connecting(monkeypatch):
    prompts = []
    monkeypatch.setattr(cli, "load_imap_settings", lambda path: ImapSettings("imap.example.org", "me@example.org"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "")
    monkeypatch.setattr(cli, "FolderCatalog", lambda **kwargs: pytest.fail("empty password must not connect"))

    result = CliRunner().invoke(cli.app, ["folders"])

    assert result.exit_code == 2
    assert prompts == ["IMAP password: "]
    assert "Empty password; aborting." in result.output


def test_folders_no_counts_displays_unavailable_counts(monkeypatch):
    output = StringIO()
    errors = StringIO()
    state = _configure_folders(monkeypatch, _folder_cli_rows(), output, errors)
    monkeypatch.setattr(cli, "load_imap_settings", lambda path: ImapSettings("imap.example.org", "me@example.org"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")

    result = CliRunner().invoke(cli.app, ["folders", "--no-counts"])

    assert result.exit_code == 0
    assert state["include_counts"] is False
    assert "-" in output.getvalue()
    assert "error [imap_folder_status]" not in result.output


def test_folders_partial_status_failure_renders_table_and_hides_exception_payload(monkeypatch):
    error = ImapOperationError(
        operation="imap_folder_status",
        message="could not read mailbox counts",
        folder="Legacy",
        cause_type="RuntimeError",
        server_status="NO",
    )
    output = StringIO()
    errors = StringIO()
    _configure_folders(monkeypatch, _folder_cli_rows(error), output, errors)
    monkeypatch.setattr(cli, "load_imap_settings", lambda path: ImapSettings("imap.example.org", "me@example.org"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")

    result = CliRunner().invoke(cli.app, ["folders"])

    rendered = output.getvalue()
    diagnostic = errors.getvalue()
    assert result.exit_code == 1
    assert "INBOX.Junk" in rendered and "Legacy" in rendered
    assert "?" in rendered
    assert "error [imap_folder_status]" in diagnostic
    assert "folder='Legacy'" in diagnostic
    assert "password=secret" not in result.output
    assert "private@example.org" not in result.output
    assert "RAW_SERVER_DATA" not in result.output


@pytest.mark.parametrize(
    ("fatal_stage", "operation", "message"),
    [
        ("enter", "imap_connect", "could not establish IMAP connection"),
        ("list", "imap_list_folders", "could not list IMAP folders"),
    ],
)
def test_folders_fatal_imap_error_is_safe_and_exits_one(monkeypatch, fatal_stage, operation, message):
    failure = ImapOperationError(
        operation=operation,
        message=message,
        cause_type="RuntimeError",
    )
    failure.__cause__ = RuntimeError("password=secret private@example.org RAW_SERVER_DATA")
    output = StringIO()
    errors = StringIO()
    _configure_folders(monkeypatch, (), output, errors, fatal=failure, fatal_stage=fatal_stage)
    monkeypatch.setattr(cli, "load_imap_settings", lambda path: ImapSettings("imap.example.org", "me@example.org"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")

    result = CliRunner().invoke(cli.app, ["folders"])

    assert result.exit_code == 1
    assert f"error [{operation}]" in errors.getvalue()
    assert "password=secret" not in result.output
    assert "private@example.org" not in result.output
    assert "RAW_SERVER_DATA" not in result.output


def test_folders_renders_server_names_as_plain_text(monkeypatch):
    name = "[red]INBOX.Junk[/red]"
    row = FolderInfo(name, ".", {b"\\JUNK"}, 1, 0)
    output = StringIO()
    errors = StringIO()
    _configure_folders(monkeypatch, (row,), output, errors)
    monkeypatch.setattr(cli, "load_imap_settings", lambda path: ImapSettings("imap.example.org", "me@example.org"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")

    result = CliRunner().invoke(cli.app, ["folders", "--no-counts"])

    assert result.exit_code == 0
    assert name in output.getvalue()
