from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner
from vaultconfig.secrets import DEFAULT_MIN_PASSPHRASE_LENGTH, FileVault

from imapledger import cli
from imapledger.application import legacy_clean
from imapledger.application.legacy_clean import LegacyCleanResult
from imapledger.classifier import SemanticSpamSignals
from imapledger.cleaner import CleanReport, MessageResult, SpamOutcome
from imapledger.config import (
    ActionKind,
    AuthSource,
    ClassificationStateBackend,
    ClassificationStateSettings,
    ImapAuthSettings,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    load_settings,
)
from imapledger.credentials import CredentialStatus, credential_status, resolve_credential
from imapledger.mailbox import (
    FolderInfo,
    ImapOperationError,
    MailboxItem,
    MailboxProbe,
    MessageSelection,
    MessageSort,
    PartialDeleteError,
    ScopedMailbox,
)
from imapledger.message import MailMessage
from imapledger.policy import SpamVerdict
from imapledger.routing_config import load_routing_rules, write_routing_rules
from imapledger.routing_models import RoutingRule, RuleType
from imapledger.routing_models import RuleSet as RoutingRuleSet
from imapledger.rules import RuleMatch, RuleSet
from tests.fakes import FolderAwareFakeClient


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


def test_clean_without_folder_is_usage_error(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_password", lambda _imap: pytest.fail("must not connect"))

    result = CliRunner().invoke(cli.app, ["clean"])

    assert result.exit_code == 2
    assert "Missing argument 'folder'" in result.output
    assert "spam.folders" not in result.output


def test_clean_help_exposes_unified_rule_options():
    result = CliRunner().invoke(cli.app, ["clean", "--help"])

    assert result.exit_code == 0
    assert "--verbose" in result.output
    assert "--apply" in result.output
    assert "--limit" in result.output
    assert "--rule" in result.output
    assert "--retry-errors" in result.output
    assert "Deprecated alias" in result.output
    assert "category actions" not in result.output


class CleanFakeMailbox:
    folder = "Spam"
    capabilities = frozenset({b"MOVE", b"UIDPLUS"})
    permanent_flags = frozenset({b"\\*"})
    permanent_flags_known = True
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
    monkeypatch.setattr(cli, "load_rules", lambda path, *, source_folders: RuleSet())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")

    class FakeLegacyCleanOperation:
        def __init__(self, _settings, _rules):
            pass

        def validate_config(self):
            return None

        def run(self, request, *, password, event_callback=None, on_folder_start=None, on_result=None):
            selection = MessageSelection(
                limit=request.limit,
                offset=request.offset,
                sort=request.sort,
            )
            observed["apply"] = request.apply
            observed["reclassify"] = request.reclassify
            observed["selection"] = selection
            observed["on_result"] = on_result
            assert password == "secret"
            selected_count = mailbox.selected_count(selection)
            if on_folder_start is not None:
                on_folder_start("Spam", len(mailbox.uids), selected_count, None, selection)
            if on_result is not None:
                for position, row in enumerate(report.results, start=1):
                    on_result("Spam", row, position, len(report.results))
            return LegacyCleanResult((report,), (), False)

    monkeypatch.setattr(cli, "LegacyCleanOperation", FakeLegacyCleanOperation)
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


@pytest.mark.parametrize(
    "arguments",
    [["clean", "--limit", "0"], ["clean", "--offset", "-1"], ["clean", "--sort", "invalid"]],
)
def test_clean_rejects_invalid_selection_options(arguments):
    result = CliRunner().invoke(cli.app, arguments)

    assert result.exit_code != 0


def test_rule_clean_output_shows_action_and_rule_without_spam_signals(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    row = MessageResult(
        uid=43627,
        subject="Delivery failed",
        sender="mailer-daemon@gmx.net",
        verdict=None,
        signals=None,
        reasons=("rule:mailer-daemon-gmx-net",),
        status="rule",
        inclination="RULE",
        action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        decision_source="rule",
        matched_rule_id="mailer-daemon-gmx-net",
    )

    cli._print_result(row, folder="INBOX.Junk", position=8, total=10, apply=False)

    rendered = output.getvalue()
    assert "[8/10] Folder=INBOX.Junk UID 43627  Action=WOULD MOVE -> INBOX.Trash" in rendered
    assert "Rule=mailer-daemon-gmx-net" in rendered
    assert "Outcome=" not in rendered
    assert "Verdict=" not in rendered
    assert "Signals=" not in rendered


def test_progress_reports_persisted_state(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    row = MessageResult(
        uid=52,
        subject="kept",
        sender="user@example.org",
        verdict=SpamVerdict.KEEP,
        signals=None,
        reasons=(),
        status="keep",
        inclination="KEEP",
        state_source="imap-keyword",
        state_persisted=True,
    )

    cli._print_result(row, folder="INBOX.Junk", position=1, total=1, apply=True)

    assert "State=STORED" in output.getvalue()


class DoctorFakeClient:
    def __init__(
        self,
        *,
        size=1,
        uids=(10,),
        fail_on=None,
        existing_folders=("Spam",),
        permanent_flags=(b"\\Answered", b"\\Flagged", b"\\Draft", b"\\Deleted", b"\\Seen", b"\\*"),
    ):
        self.size = size
        self.uids = list(uids)
        self.use_uid = True
        self.fail_on = fail_on
        self.selected = []
        self.fetches = []
        self.added = []
        self.removed = []
        self.expunged = []
        self.logged_out = False
        self.existing_folders = set(existing_folders)
        self.folder_queries = []
        self.permanent_flags = permanent_flags

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
        return {
            b"UIDVALIDITY": 42,
            b"EXISTS": len(self.uids),
            b"PERMANENTFLAGS": self.permanent_flags,
        }

    def search(self, criteria="ALL", charset=None):
        return self.uids

    def fetch(self, messages, data, modifiers=None):
        messages = (messages,) if isinstance(messages, str) else tuple(messages)
        data = tuple(data)
        self.fetches.append((messages, data))
        if data == ("UID",):
            requested = self.uids if messages == ("1:*",) else messages
            return {
                uid: {b"UID": uid, b"SEQ": sequence}
                for sequence, uid in enumerate(self.uids, start=1)
                if uid in requested
            }
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
    monkeypatch.setattr(cli, "load_rules", lambda path, *, source_folders: RuleSet())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")

    def mailbox_factory(**kwargs):
        return ScopedMailbox(
            **kwargs,
            client_factory=lambda *args, **options: factory_options.update(options) or client,
        )

    monkeypatch.setattr(cli, "ScopedMailbox", mailbox_factory)
    monkeypatch.setattr(cli, "PyJevSpamClassifier", lambda: pytest.fail("doctor constructed classifier"))
    monkeypatch.setattr(legacy_clean, "ScopedMailbox", mailbox_factory)
    monkeypatch.setattr(
        legacy_clean,
        "PyJevSpamClassifier",
        lambda **kwargs: pytest.fail("legacy clean constructed classifier"),
    )
    return factory_options


def _keyword_state_settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(
            folders=("Spam",),
            state=ClassificationStateSettings(ClassificationStateBackend.IMAP_KEYWORDS),
        ),
    )


def _configure_keyword_state_cli(monkeypatch, client, settings=None):
    settings = settings or _keyword_state_settings()
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli, "load_rules", lambda path, *, source_folders: RuleSet())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "secret")
    monkeypatch.setattr(
        cli,
        "ScopedMailbox",
        lambda **kwargs: ScopedMailbox(**kwargs, client_factory=lambda *args, **options: client),
    )
    return settings


def _state_raw_message(subject, body=b"PRIVATE BODY CONTENT"):
    return (
        f"From: sender@example.net\r\n"
        f"To: user@example.org\r\n"
        f"Subject: {subject}\r\n"
        "Date: Tue, 01 Jan 2030 00:00:00 +0000\r\n"
        "Message-ID: <message@example.net>\r\n"
        "Authentication-Results: mx.example.net; spf=pass; dmarc=pass\r\n"
        "X-Spam-Flag: YES\r\n"
        "X-Spam-Status: Yes, score=5.0\r\n\r\n"
    ).encode() + body


def test_state_status_counts_keyword_markers_without_fetching_messages(monkeypatch):
    client = FolderAwareFakeClient(
        {"Spam": {uid: _state_raw_message(f"message {uid}") for uid in (10, 20, 30, 40)}},
        flags={
            "Spam": {
                10: {b"imapledger-v1-spam"},
                20: {b"imapledger-v1-notspam"},
                30: {b"imapledger-v1-review", b"imapledger-v1-notspam"},
                40: {b"\\seen"},
            }
        },
    )
    _configure_keyword_state_cli(monkeypatch, client)

    result = CliRunner().invoke(cli.app, ["state", "status"])

    assert result.exit_code == 0
    assert "Classification state" in result.output
    assert "uidvalidity=42" in result.output
    assert "total=4 spam=1 notspam=2 review=1 unclassified=1 conflicts=1" in " ".join(result.output.split())
    assert client.fetches == [(("1:*",), ("UID",))]
    assert client.added == client.removed == client.expunged == []


def test_state_reset_is_dry_run_by_default_and_apply_is_exact_uid_scoped(monkeypatch):
    client = FolderAwareFakeClient(
        {
            "Spam": {10: _state_raw_message("marked"), 20: _state_raw_message("other")},
            "Archive": {30: _state_raw_message("outside configured source")},
        },
        flags={
            "Spam": {
                10: {b"imapledger-v1-spam", b"imapledger-v1-notspam", b"\\seen"},
                20: {b"imapledger-v1-review"},
            },
            "Archive": {30: {b"imapledger-v1-review"}},
        },
    )
    _configure_keyword_state_cli(monkeypatch, client)

    preview = CliRunner().invoke(cli.app, ["state", "reset", "--folder", "Spam", "--uid", "10"])

    assert preview.exit_code == 0
    assert "would remove" in " ".join(preview.output.split())
    assert "imapledger-v1-spam" in preview.output
    assert client.removed == []

    applied = CliRunner().invoke(cli.app, ["state", "reset", "--folder", "Spam", "--uid", "10", "--apply"])

    assert applied.exit_code == 0
    assert client.removed == [
        ((10,), ("imapledger-v1-spam",), True),
        ((10,), ("imapledger-v1-notspam",), True),
    ]
    assert client.flags["Spam"][10] == {b"\\seen"}
    assert b"imapledger-v1-review" in client.flags["Spam"][20]
    assert b"imapledger-v1-review" in client.flags["Archive"][30]
    assert client.expunged == []


def test_state_reset_rejects_uid_outside_the_initial_snapshot(monkeypatch):
    client = FolderAwareFakeClient(
        {"Spam": {10: _state_raw_message("marked")}},
        flags={"Spam": {10: {b"imapledger-v1-spam"}}},
    )
    _configure_keyword_state_cli(monkeypatch, client)

    result = CliRunner().invoke(cli.app, ["state", "reset", "--folder", "Spam", "--uid", "99", "--apply"])

    assert result.exit_code == 1
    assert "refusing UID outside initial mailbox snapshot" in result.output
    assert client.removed == []


def test_state_reset_requires_all_for_an_unbounded_folder_reset(monkeypatch):
    client = FolderAwareFakeClient({"Spam": {10: _state_raw_message("marked")}})
    _configure_keyword_state_cli(monkeypatch, client)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("invalid reset prompted for a password"))

    result = CliRunner().invoke(cli.app, ["state", "reset", "--folder", "Spam"])

    assert result.exit_code == 2
    assert "unbounded reset requires --all" in result.output
    assert client.calls == []


def test_review_list_fetches_only_bounded_headers_and_does_not_construct_classifier(monkeypatch):
    client = FolderAwareFakeClient(
        {
            "Spam": {
                10: _state_raw_message("review 10"),
                20: _state_raw_message("review 20"),
                30: _state_raw_message("other"),
            }
        },
        flags={"Spam": {10: {b"imapledger-v1-review"}, 20: {b"imapledger-v1-review"}}},
    )
    _configure_keyword_state_cli(monkeypatch, client)
    monkeypatch.setattr(cli, "PyJevSpamClassifier", lambda **kwargs: pytest.fail("review list constructed classifier"))

    result = CliRunner().invoke(
        cli.app,
        ["review", "list", "--folder", "Spam", "--limit", "1", "--offset", "1", "--sort", "newest"],
    )

    assert result.exit_code == 0
    assert "review 10" in result.output
    assert "review 20" not in result.output
    assert "PRIVATE BODY CONTENT" not in result.output
    assert client.fetches == [
        (("1:*",), ("UID",)),
        ((10,), ("BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]",)),
    ]
    assert client.added == client.removed == client.expunged == []


def test_explain_uses_header_only_for_persisted_state_and_skips_classifier(monkeypatch):
    client = FolderAwareFakeClient(
        {"Spam": {10: _state_raw_message("stored spam")}},
        flags={"Spam": {10: {b"imapledger-v1-spam"}}},
    )
    _configure_keyword_state_cli(monkeypatch, client)
    monkeypatch.setattr(
        cli,
        "PyJevSpamClassifier",
        lambda **kwargs: pytest.fail("cached explain constructed classifier"),
    )

    result = CliRunner().invoke(cli.app, ["explain", "10", "--folder", "Spam"])

    assert result.exit_code == 0
    assert "persisted_state=SPAM" in result.output
    assert "Authentication evidence=not fetched" in result.output
    assert "Classifier: NOT RUN" in result.output
    assert "PRIVATE BODY CONTENT" not in result.output
    assert all(data != ("BODY.PEEK[]",) for _, data in client.fetches)
    assert client.added == client.removed == client.expunged == []


def test_explain_reclassify_reports_evidence_signals_and_policy_without_mutating(monkeypatch):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(
            folders=("Spam",),
            state=ClassificationStateSettings(ClassificationStateBackend.IMAP_KEYWORDS),
            trusted_authserv_ids=("mx.example.net",),
            trusted_provider_headers=("x-spam-status",),
        ),
    )
    client = FolderAwareFakeClient(
        {"Spam": {10: _state_raw_message("stored spam")}},
        flags={"Spam": {10: {b"imapledger-v1-spam"}}},
    )
    _configure_keyword_state_cli(monkeypatch, client, settings=settings)
    assessed = []

    class ExplainClassifier:
        def __init__(self, *, trusted_authserv_ids, trusted_provider_headers):
            self.trusted_authserv_ids = trusted_authserv_ids
            self.trusted_provider_headers = trusted_provider_headers

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def assess(self, message):
            assessed.append(message.uid)
            evidence = cli.build_message_evidence(
                message,
                trusted_authserv_ids=self.trusted_authserv_ids,
                trusted_provider_headers=self.trusted_provider_headers,
            )
            return SimpleNamespace(
                signals=SemanticSpamSignals(0.2, 0.1, 0.1, 0.1, 0.1),
                evidence=evidence,
            )

    monkeypatch.setattr(cli, "PyJevSpamClassifier", ExplainClassifier)

    result = CliRunner().invoke(cli.app, ["explain", "10", "--folder", "Spam", "--reclassify"])

    assert result.exit_code == 0
    assert assessed == [10]
    assert "persisted_state=SPAM" in result.output
    assert "Authentication trusted=True" in result.output
    assert "Provider spam_flag=True" in result.output
    assert "Signals bulk=0.20" in result.output
    assert "Policy verdict=REVIEW" in result.output
    assert "PRIVATE BODY CONTENT" not in result.output
    assert any(data == ("BODY.PEEK[]",) for _, data in client.fetches)
    assert client.added == client.removed == client.expunged == []


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
    assert client.selected == [("Spam", True), ("Spam", True), ("Spam", True)]
    assert client.fetches == [(("1:*",), ("UID",)), ((10,), ("RFC822.SIZE",)), ((10,), ("BODY.PEEK[]",))]
    assert client.added == client.removed == client.expunged == []
    assert client.logged_out
    assert factory_options["use_uid"] is True


def test_doctor_reports_imap_keyword_persistence_support(monkeypatch):
    client = DoctorFakeClient()
    _configure_doctor(monkeypatch, client, settings=_keyword_state_settings())

    result = CliRunner().invoke(cli.app, ["doctor"])

    assert result.exit_code == 0
    assert "classification state backend: imap-keywords" in result.output
    assert "PERMANENTFLAGS:" in result.output
    assert "custom keyword persistence: OK" in result.output
    assert client.added == client.removed == []


def test_doctor_reports_unknown_keyword_persistence_without_mutating(monkeypatch):
    client = DoctorFakeClient(permanent_flags=None)
    _configure_doctor(monkeypatch, client, settings=_keyword_state_settings())

    result = CliRunner().invoke(cli.app, ["doctor"])

    assert result.exit_code == 0
    assert "custom keyword persistence: UNKNOWN in read-only probe" in result.output
    assert client.added == client.removed == []


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
    assert client.selected == [
        ("INBOX.Junk", True),
        ("INBOX.Junk", True),
        ("INBOX.Junk", True),
        ("INBOX.Later", True),
        ("INBOX.Later", True),
        ("INBOX.Later", True),
    ]
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
    assert [selector for _, selector in client.fetches] == [("UID",), ("RFC822.SIZE",)]


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
    assert 'backend = "none"' in rendered
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
    assert settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS
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
    rules=None,
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
    monkeypatch.setattr(cli, "load_rules", lambda path, *, source_folders: rules if rules is not None else RuleSet())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: state["prompts"].append(prompt) or "secret")

    class FakeMailbox:
        def __init__(self, **kwargs):
            self.folder = kwargs["folder"]
            self.kwargs = kwargs
            self.uids = frozenset(range(1, 31))
            self.capabilities = frozenset({b"MOVE", b"UIDPLUS"})
            self.permanent_flags = frozenset({b"\\*"})
            self.permanent_flags_known = True
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

    monkeypatch.setattr(legacy_clean, "ScopedMailbox", FakeMailbox)

    class CountingClassifier:
        def __init__(self, **kwargs):
            self.options = kwargs
            state["classifier_instances"].append(self)

        def __enter__(self):
            state["classifier_contexts"].append(self)
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(legacy_clean, "PyJevSpamClassifier", CountingClassifier)

    class FakeCleaner:
        def __init__(self, mailbox, classifier, *, policy, actions, rules=None, state_backend=None):
            self.mailbox = mailbox
            self.rules = rules
            self.classifier = classifier
            self.actions = actions

        def run(self, *, apply, selection, on_result, reclassify=False):
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

    monkeypatch.setattr(legacy_clean, "SpamCleaner", FakeCleaner)
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


def test_doctor_checks_all_source_folders_capabilities_and_destinations(monkeypatch):
    settings = _multi_folder_settings()
    probes = []
    selections = []
    prompts = []
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli, "load_rules", lambda path, *, source_folders: RuleSet())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "secret")
    monkeypatch.setattr(cli, "PyJevSpamClassifier", lambda **kwargs: pytest.fail("doctor constructed classifier"))

    class DoctorScope:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.folder = kwargs["folder"]
            self.capabilities = {b"MOVE"}
            self.permanent_flags = frozenset({b"\\*"})
            self.permanent_flags_known = True

        def __enter__(self):
            selections.append((self.folder, self.kwargs["writable"]))
            return self

        def __exit__(self, *args):
            return None

        def snapshot(self):
            return self

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
    monkeypatch.setattr(cli, "load_rules", lambda path, *, source_folders: RuleSet())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "secret")

    class DoctorScope:
        def __init__(self, **kwargs):
            self.folder = kwargs["folder"]
            self.kwargs = kwargs
            self.capabilities = {b"MOVE"} if self.folder == "INBOX.Junk" else set()
            self.permanent_flags = frozenset({b"\\*"})
            self.permanent_flags_known = True

        def __enter__(self):
            assert self.kwargs["writable"] is False
            return self

        def __exit__(self, *args):
            return None

        def snapshot(self):
            return self

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
    assert "Credential error: IMAP password must not be empty" in result.output


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


def _routing_settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("INBOX.Junk",)),
    )


def _routing_message(uid: int = 43627, *, address: str = "mailer-daemon@gmx.net") -> MailMessage:
    return MailMessage(
        uid=uid,
        subject="Delivery failure notice",
        sender=f"Mailer Daemon <{address}>",
        recipients=(),
        date="",
        body="private message body",
        from_display_name="Mailer Daemon",
        from_address=address,
    )


def _install_rule_learn(monkeypatch, tmp_path, *, status="auto"):
    state = {"fetches": [], "saved": [], "proposals": [], "events": []}
    settings = _routing_settings()
    rule = RoutingRule(
        id="newsletter",
        enabled=True,
        type=RuleType.SEMANTIC,
        destination="Archive",
        description="Route newsletter messages",
    )
    matcher = RuleMatch(from_address="mailer-daemon@gmx.net")
    proposal = SimpleNamespace(
        semantic_fit=0.96,
        selected_candidate=SimpleNamespace(description="Exact sender address"),
        candidate_confidence=0.96,
        safe_probability=0.98,
        proposed_matcher=matcher,
        status=status,
    )
    message = _routing_message()

    class FakeMailbox:
        def __init__(self, **kwargs):
            state["mailbox_kwargs"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def fetch_uid(self, uid):
            state["fetches"].append(uid)
            state["events"].append("fetch")
            return MailboxItem(uid, message)

    class FakeOperation:
        def propose(self, current_message, *, folder, target_rule_id, existing_rules):
            state["proposals"].append((current_message, folder, target_rule_id, existing_rules))
            return proposal

        def save(self, current_proposal, service):
            state["saved"].append((current_proposal, service))
            state["events"].append("save")
            return SimpleNamespace(changed_rule_id="newsletter")

    output = StringIO()
    state["output"] = output
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)
    monkeypatch.setattr(cli, "load_routing_rules", lambda _path: RoutingRuleSet((rule,)))
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "secret")
    monkeypatch.setattr(cli, "ScopedMailbox", FakeMailbox)
    monkeypatch.setattr(cli, "RuleLearningOperation", FakeOperation)
    return state, proposal


def _learn_args(tmp_path, *extra):
    return [
        "rule",
        "learn",
        "newsletter",
        "--folder",
        "INBOX",
        "--uid",
        "43627",
        "--config",
        str(tmp_path / "config.toml"),
        *extra,
    ]


def test_rule_help_and_learn_require_folder():
    runner = CliRunner()
    help_result = runner.invoke(cli.app, ["rule", "--help"])
    missing_folder = runner.invoke(cli.app, ["rule", "learn", "newsletter", "--uid", "43627"])

    assert help_result.exit_code == 0
    assert all(
        name in help_result.output
        for name in ("add", "edit", "learn", "list", "show", "remove", "test", "preview", "apply")
    )
    assert missing_folder.exit_code == 2
    assert "--folder" in missing_folder.output


def test_rule_learn_validates_uid_and_existing_target_before_password(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: pytest.fail("validation prompted for a password"))
    invalid_uid = CliRunner().invoke(
        cli.app,
        ["rule", "learn", "newsletter", "--folder", "INBOX", "--uid", "0"],
    )
    monkeypatch.setattr(cli, "load_settings", lambda _path: _routing_settings())
    monkeypatch.setattr(cli, "load_routing_rules", lambda _path: RoutingRuleSet())
    missing_rule = CliRunner().invoke(cli.app, _learn_args(tmp_path))

    assert invalid_uid.exit_code == 2
    assert "greater than or equal to 1" in invalid_uid.output
    assert missing_rule.exit_code == 2
    assert "Rule not found: newsletter" in missing_rule.output


def test_rule_learn_saves_only_matcher_and_never_moves_example(monkeypatch, tmp_path):
    state, _ = _install_rule_learn(monkeypatch, tmp_path)

    result = CliRunner().invoke(cli.app, _learn_args(tmp_path, "--yes"))

    assert result.exit_code == 0, result.output
    assert state["mailbox_kwargs"]["writable"] is False
    assert "allowed_destinations" not in state["mailbox_kwargs"]
    assert state["fetches"] == [43627]
    assert state["events"] == ["fetch", "save"]
    assert len(state["saved"]) == 1
    assert state["proposals"][0][1:3] == ("INBOX", "newsletter")
    assert "Saved matcher to rule newsletter" in state["output"].getvalue()
    assert "INBOX is not configured" not in result.output
    assert "MOVED" not in result.output


def test_rule_learn_preview_never_saves_even_with_yes(monkeypatch, tmp_path):
    state, _ = _install_rule_learn(monkeypatch, tmp_path)

    result = CliRunner().invoke(cli.app, _learn_args(tmp_path, "--preview", "--yes"))

    assert result.exit_code == 0, result.output
    assert state["saved"] == []
    assert state["events"] == ["fetch"]
    assert "Preview only. No matcher was saved." in state["output"].getvalue()


def test_rule_learn_review_proposal_is_not_saved(monkeypatch, tmp_path):
    state, _ = _install_rule_learn(monkeypatch, tmp_path, status="review")

    result = CliRunner().invoke(cli.app, _learn_args(tmp_path, "--yes"))

    assert result.exit_code == 0, result.output
    assert state["saved"] == []
    assert "No matcher was saved." in state["output"].getvalue()


def test_rule_learn_confirmation_defaults_to_no(monkeypatch, tmp_path):
    state, _ = _install_rule_learn(monkeypatch, tmp_path)
    confirmations = []
    monkeypatch.setattr(cli.typer, "confirm", lambda _prompt, *, default: confirmations.append(default) or False)

    result = CliRunner().invoke(cli.app, _learn_args(tmp_path))

    assert result.exit_code == 0
    assert confirmations == [False]
    assert state["saved"] == []
    assert "No matcher was saved." in state["output"].getvalue()


def test_rule_list_show_remove_do_not_prompt_for_password(monkeypatch, tmp_path):
    config = tmp_path / "config.toml"
    path = config.with_name("rules.toml")
    rule = RoutingRule(
        id="mailer-daemon-gmx-net",
        enabled=True,
        type=RuleType.HEADER,
        destination="INBOX.Trash",
        match=RuleMatch(from_address="mailer-daemon@gmx.net"),
        source_folders=("INBOX.Junk",),
    )
    write_routing_rules(RoutingRuleSet((rule,)), path)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("management command prompted"))
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))

    listed = CliRunner().invoke(cli.app, ["rule", "list", "--config", str(config)])
    shown = CliRunner().invoke(cli.app, ["rule", "show", rule.id, "--config", str(config)])
    deleted = CliRunner().invoke(cli.app, ["rule", "remove", rule.id, "--yes", "--config", str(config)])

    assert listed.exit_code == 0 and rule.id in output.getvalue()
    assert shown.exit_code == 0 and "from=mailer-daemon@gmx.net" in output.getvalue()
    assert deleted.exit_code == 0 and f"Removed rule {rule.id}" in output.getvalue()
    assert load_routing_rules(path).rules == ()


def test_rule_test_evaluates_one_exact_message_read_only(monkeypatch, tmp_path):
    settings = _routing_settings()
    rule = RoutingRule(
        id="mailer-daemon-gmx-net",
        enabled=True,
        type=RuleType.HEADER,
        destination="INBOX.Trash",
        match=RuleMatch(from_address="mailer-daemon@gmx.net"),
    )
    state, _ = _install_rule_learn(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)
    monkeypatch.setattr(cli, "load_routing_rules", lambda _path: RoutingRuleSet((rule,)))
    monkeypatch.setattr(cli, "PyJevSpamClassifier", lambda **kwargs: pytest.fail("rule test ran spam classifier"))

    result = CliRunner().invoke(
        cli.app,
        [
            "rule",
            "test",
            rule.id,
            "--folder",
            "INBOX.Junk",
            "--uid",
            "43627",
            "--config",
            str(tmp_path / "config.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert state["mailbox_kwargs"]["writable"] is False
    assert state["fetches"] == [43627]
    assert "Folder=INBOX.Junk UID 43627 MATCH" in state["output"].getvalue()
    assert "Read-only; no actions were executed." in state["output"].getvalue()


def _write_auth_config(
    path,
    source=AuthSource.PROMPT,
    *,
    vault_path=None,
    vault_min_passphrase_length=DEFAULT_MIN_PASSPHRASE_LENGTH,
):
    settings = Settings(
        imap=ImapSettings(
            host="imap.example.org",
            username="me@example.org",
            auth=ImapAuthSettings(source, vault_path, vault_min_passphrase_length),
        ),
        spam=SpamSettings(folders=("Spam",)),
    )
    cli.write_settings(settings, path)
    return settings


@pytest.mark.parametrize(
    ("storage_args", "source", "expected_prompts"),
    [
        ([], AuthSource.KEYRING, ["IMAP password: "]),
        (
            ["--storage", "encrypted-file"],
            AuthSource.VAULT,
            ["IMAP password: ", "Choose master passphrase (minimum 12 characters): ", "Confirm master passphrase: "],
        ),
    ],
)
def test_auth_set_selects_storage_and_keeps_secrets_out_of_config_and_output(
    monkeypatch,
    tmp_path,
    storage_args,
    source,
    expected_prompts,
):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path)
    vault_path = tmp_path / "credentials.enc"
    if source is AuthSource.VAULT:
        monkeypatch.setattr(cli, "default_credential_vault_path", lambda: vault_path)

    entered = iter(
        ("do-not-print-this", "vault passphrase that is long enough", "vault passphrase that is long enough")
    )
    prompts = []
    stored = []
    selected_storage = []
    monkeypatch.setattr(
        cli.getpass,
        "getpass",
        lambda prompt: prompts.append(prompt) or next(entered),
    )

    class FakeBackend:
        def __init__(self, selected_source, selected_vault_path):
            self.source = selected_source
            self.vault_path = selected_vault_path

        def create(self, ref, password, *, passphrase=None):
            stored.append((ref, password, self.source, {"passphrase": passphrase}))

        def replace(self, ref, password, *, passphrase=None):
            stored.append((ref, password, self.source, {"passphrase": passphrase}))

        def delete(self, ref, *, passphrase=None):
            return True

    monkeypatch.setattr(
        cli,
        "credential_backend_for_storage",
        lambda storage, *, vault_path=None, vault_min_passphrase_length=12: (
            selected_storage.append(storage) or FakeBackend(source, vault_path)
        ),
    )

    result = CliRunner().invoke(
        cli.app,
        ["auth", "set", *storage_args, "--config", str(config_path)],
    )

    assert result.exit_code == 0, result.output
    assert selected_storage == [storage_args[-1] if storage_args else "auto"]
    assert prompts == expected_prompts
    assert stored[0][1] == "do-not-print-this"
    assert stored[0][2] is source
    assert load_settings(config_path).imap.auth.source is source
    config_text = config_path.read_text(encoding="utf-8").lower()
    assert "do-not-print-this" not in config_text
    assert "vault passphrase" not in config_text
    assert "do-not-print-this" not in result.output
    assert "vault passphrase" not in result.output
    assert "password" not in config_text


def test_auth_vault_cli_roundtrips_a_secret_without_serializing_it(
    monkeypatch,
    tmp_path,
):
    config_path = tmp_path / "config.toml"
    vault_path = tmp_path / "data" / "credentials.enc"
    _write_auth_config(config_path, vault_min_passphrase_length=10)
    monkeypatch.setattr(cli, "default_credential_vault_path", lambda: vault_path)

    password = "unique-imap-password-value"
    passphrase = "1234567890"
    inputs = iter((password, passphrase, passphrase))
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or next(inputs))
    result = CliRunner().invoke(
        cli.app,
        ["auth", "set", "--storage", "vault", "--config", str(config_path)],
    )

    assert result.exit_code == 0, result.output
    assert prompts == [
        "IMAP password: ",
        "Choose master passphrase (minimum 10 characters): ",
        "Confirm master passphrase: ",
    ]
    assert password not in result.output
    assert passphrase not in result.output
    assert password not in config_path.read_text(encoding="utf-8")
    assert passphrase not in config_path.read_text(encoding="utf-8")
    encrypted = vault_path.read_bytes()
    assert password.encode() not in encrypted
    assert passphrase.encode() not in encrypted

    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: passphrase)
    resolved = cli.resolve_credential(load_settings(config_path).imap, vault_path=vault_path)
    assert resolved.password == password
    assert password not in repr(resolved)


def test_auth_set_reports_custom_minimum_for_short_new_vault_passphrase(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    vault_path = tmp_path / "credentials.enc"
    _write_auth_config(config_path, vault_min_passphrase_length=10)
    monkeypatch.setattr(cli, "default_credential_vault_path", lambda: vault_path)

    password = "UNIQUE_IMAP_PASSWORD_SENTINEL"
    short_passphrase = "123456789"
    values = iter((password, short_passphrase, short_passphrase))
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or next(values))
    result = CliRunner().invoke(cli.app, ["auth", "set", "--storage", "vault", "--config", str(config_path)])

    assert result.exit_code == 2
    assert "Master passphrase must be at least 10 characters" in result.output
    assert "Configure [imap.auth].vault_min_passphrase_length" in result.output
    assert short_passphrase not in result.output
    assert password not in result.output
    assert prompts == [
        "IMAP password: ",
        "Choose master passphrase (minimum 10 characters): ",
        "Confirm master passphrase: ",
    ]
    settings = load_settings(config_path)
    assert settings.imap.auth.source is AuthSource.PROMPT
    assert settings.imap.auth.vault_min_passphrase_length == 10
    assert not vault_path.exists()


def test_auth_set_existing_vault_uses_generic_prompt_and_unlocks_short_passphrase(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    vault_path = tmp_path / "credentials.enc"
    passphrase = "1234567890"
    FileVault(vault_path, min_passphrase_length=10).initialize(passphrase)
    _write_auth_config(
        config_path,
        AuthSource.VAULT,
        vault_path=vault_path,
        vault_min_passphrase_length=DEFAULT_MIN_PASSPHRASE_LENGTH,
    )

    password = "UNIQUE_REPLACED_IMAP_PASSWORD"
    values = iter((password, passphrase))
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or next(values))
    result = CliRunner().invoke(
        cli.app,
        ["auth", "set", "--storage", "vault", "--replace", "--config", str(config_path)],
    )

    assert result.exit_code == 0, result.output
    assert prompts == ["IMAP password: ", "Credential vault passphrase: "]
    assert passphrase not in result.output
    assert password not in result.output
    settings = load_settings(config_path)
    assert settings.imap.auth.vault_min_passphrase_length == DEFAULT_MIN_PASSPHRASE_LENGTH
    resolved = cli.resolve_credential(settings.imap, prompt_secret=lambda prompt: passphrase)
    assert resolved.password == password


def test_configured_vault_path_flows_through_auth_commands_and_runtime(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg"))

    config_path = tmp_path / "config.toml"
    configured_path = Path("~/custom.enc")
    actual_path = home / "custom.enc"
    _write_auth_config(config_path, vault_path=configured_path, vault_min_passphrase_length=10)
    imap_password = "UNIQUE_IMAP_PASSWORD_SENTINEL"
    old_passphrase = "UNIQUE_MASTER_PASSPHRASE_SENTINEL"
    new_passphrase = "UNIQUE_NEW_MASTER_PASSPHRASE_SENTINEL"
    prompts = iter((imap_password, old_passphrase, old_passphrase))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(prompts))

    stored = CliRunner().invoke(
        cli.app,
        ["auth", "set", "--storage", "vault", "--config", str(config_path)],
    )

    assert stored.exit_code == 0, stored.output
    assert actual_path.exists()
    assert load_settings(config_path).imap.auth.vault_path == configured_path
    assert load_settings(config_path).imap.auth.vault_min_passphrase_length == 10
    assert not (home / "xdg" / "imapledger" / "credentials.enc").exists()
    assert imap_password not in stored.output
    assert old_passphrase not in stored.output
    assert imap_password not in config_path.read_text(encoding="utf-8")
    assert old_passphrase not in config_path.read_text(encoding="utf-8")

    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("status must not prompt"))
    status = CliRunner().invoke(cli.app, ["auth", "status", "--verbose", "--config", str(config_path)])

    assert status.exit_code == 0, status.output
    assert "entry count: 1" in status.output
    assert "account credential: unknown until unlock" in status.output
    assert imap_password not in status.output
    assert "new-passphrase minimum: 10 characters (local config)" in status.output
    assert old_passphrase not in status.output
    assert credential_status(load_settings(config_path).imap).vault_path == actual_path

    passphrases = iter((old_passphrase, new_passphrase, new_passphrase))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(passphrases))
    changed = CliRunner().invoke(cli.app, ["auth", "change-passphrase", "--config", str(config_path)])

    assert changed.exit_code == 0, changed.output
    assert old_passphrase not in changed.output
    assert new_passphrase not in changed.output
    settings = load_settings(config_path)
    assert settings.imap.auth.source is AuthSource.VAULT
    assert settings.imap.auth.vault_path == configured_path
    assert settings.imap.auth.vault_min_passphrase_length == 10
    resolved = resolve_credential(settings.imap, prompt_secret=lambda prompt: new_passphrase)
    assert resolved.password == imap_password
    assert imap_password not in repr(resolved)

    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: new_passphrase)
    deleted = CliRunner().invoke(cli.app, ["auth", "delete", "--yes", "--config", str(config_path)])

    assert deleted.exit_code == 0, deleted.output
    assert imap_password not in deleted.output
    assert new_passphrase not in deleted.output
    settings = load_settings(config_path)
    assert settings.imap.auth.source is AuthSource.PROMPT
    assert settings.imap.auth.vault_path == configured_path
    assert settings.imap.auth.vault_min_passphrase_length == 10
    assert (
        credential_status(
            ImapSettings(
                host=settings.imap.host,
                username=settings.imap.username,
                port=settings.imap.port,
                auth=ImapAuthSettings(AuthSource.VAULT, configured_path),
            ),
            master_passphrase=new_passphrase,
        ).available
        is False
    )


def test_auth_set_refuses_overwrite_without_changing_source_or_leaking_password(
    monkeypatch,
    tmp_path,
):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "do-not-print-this")

    class ExistingCredentialBackend:
        source = AuthSource.KEYRING

        def create(self, ref, password, *, passphrase=None):
            raise cli.CredentialError("an IMAP credential already exists in the OS keyring")

        def replace(self, ref, password, *, passphrase=None):
            raise AssertionError("replacement was not requested")

        def delete(self, ref, *, passphrase=None):
            raise AssertionError("credential must not be deleted")

    monkeypatch.setattr(
        cli,
        "credential_backend_for_storage",
        lambda storage, *, vault_path=None, vault_min_passphrase_length=12: ExistingCredentialBackend(),
    )

    result = CliRunner().invoke(cli.app, ["auth", "set", "--config", str(config_path)])

    assert result.exit_code == 2
    assert "already exists" in result.output
    assert "do-not-print-this" not in result.output
    assert load_settings(config_path).imap.auth.source is AuthSource.PROMPT


def test_auth_set_replace_is_explicit_and_does_not_rewrite_source(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path, AuthSource.KEYRING)
    original_config = config_path.read_bytes()
    password = "UNIQUE_IMAP_PASSWORD_SENTINEL"
    events = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: password)

    class Backend:
        source = AuthSource.KEYRING

        def create(self, ref, value, *, passphrase=None):
            raise AssertionError("replace must not use create")

        def replace(self, ref, value, *, passphrase=None):
            events.append((ref.username, value, passphrase))

        def delete(self, ref, *, passphrase=None):
            raise AssertionError("replace must not delete first")

    monkeypatch.setattr(
        cli,
        "credential_backend_for_storage",
        lambda storage, *, vault_path=None, vault_min_passphrase_length=12: Backend(),
    )

    result = CliRunner().invoke(cli.app, ["auth", "set", "--replace", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert events == [("me@example.org", password, None)]
    assert config_path.read_bytes() == original_config
    assert load_settings(config_path).imap.auth.source is AuthSource.KEYRING
    assert password not in result.output


def test_auth_status_displays_only_source_availability_and_backend(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path, AuthSource.KEYRING)
    monkeypatch.setattr(
        cli,
        "credential_status",
        lambda imap, **kwargs: CredentialStatus(AuthSource.KEYRING, True, "SecretService", backend_available=True),
    )
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("keyring status must not prompt"))

    result = CliRunner().invoke(cli.app, ["auth", "status", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "configured source: keyring" in result.output
    assert "available: yes" in result.output
    assert "backend: SecretService" in result.output
    assert "credential present: yes" in result.output
    assert "password" not in result.output.lower()


def test_auth_delete_requires_yes_and_returns_source_to_prompt(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path, AuthSource.KEYRING)
    deleted = []

    class DeleteBackend:
        source = AuthSource.KEYRING

        def create(self, ref, value, *, passphrase=None):
            raise AssertionError("credential must not be created")

        def replace(self, ref, value, *, passphrase=None):
            raise AssertionError("credential must not be replaced")

        def delete(self, ref, *, passphrase=None):
            deleted.append(ref.username)
            return True

    monkeypatch.setattr(cli, "credential_backend_for", lambda source, **kwargs: DeleteBackend())

    declined = CliRunner().invoke(
        cli.app,
        ["auth", "delete", "--config", str(config_path)],
        input="n\n",
    )
    assert declined.exit_code == 0, declined.output
    assert deleted == []
    assert load_settings(config_path).imap.auth.source is AuthSource.KEYRING

    result = CliRunner().invoke(cli.app, ["auth", "delete", "--yes", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert deleted == ["me@example.org"]
    assert load_settings(config_path).imap.auth.source is AuthSource.PROMPT
    assert "Deleted IMAP credential from keyring storage." in result.output


def test_auth_change_passphrase_prompts_and_redacts_values(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path, AuthSource.VAULT, vault_min_passphrase_length=10)
    values = iter(
        ("old private passphrase", "new private passphrase long enough", "new private passphrase long enough")
    )
    prompts = []
    changed = []
    monkeypatch.setattr(
        cli.getpass,
        "getpass",
        lambda prompt: prompts.append(prompt) or next(values),
    )
    monkeypatch.setattr(
        cli,
        "change_credential_vault_passphrase",
        lambda old, new, **kwargs: changed.append((old, new, kwargs)),
    )

    result = CliRunner().invoke(cli.app, ["auth", "change-passphrase", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert prompts == [
        "Current master passphrase: ",
        "New master passphrase (minimum 10 characters): ",
        "Confirm new master passphrase: ",
    ]
    assert changed == [
        (
            "old private passphrase",
            "new private passphrase long enough",
            {"vault_path": None, "min_passphrase_length": 10},
        )
    ]
    assert "private passphrase" not in result.output


def test_auth_status_verbose_inspects_vault_without_prompting_for_passphrase(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    vault_path = Path("custom.enc")
    settings = Settings(
        imap=ImapSettings(
            host="imap.example.org",
            username="me@example.org",
            auth=ImapAuthSettings(AuthSource.VAULT, vault_path, 10),
        ),
        spam=SpamSettings(folders=("Spam",)),
    )
    cli.write_settings(settings, config_path)
    monkeypatch.setattr(
        cli,
        "credential_status",
        lambda imap: CredentialStatus(
            AuthSource.VAULT,
            None,
            backend_available=True,
            vault_path=vault_path,
            vault_format="v2",
            kdf_name="argon2id",
            memlimit_bytes=64 * 1024 * 1024,
            opslimit=2,
            entry_count=3,
        ),
    )
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("status must not prompt for secrets"))

    result = CliRunner().invoke(cli.app, ["auth", "status", "--verbose", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "vault:" in result.output
    assert str(vault_path) in result.output
    assert "account credential: unknown until unlock" in result.output
    assert "format: v2" in result.output
    assert "KDF: argon2id" in result.output
    assert "memory: 64 MiB" in result.output
    assert "operations: 2" in result.output
    assert "entry count: 3" in result.output
    assert "new-passphrase minimum: 10 characters (local config)" in result.output


@pytest.mark.parametrize("storage", ("auto", "keyring"))
def test_auth_set_storage_failure_shows_choices_before_secret_prompt(monkeypatch, tmp_path, storage):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path)
    monkeypatch.setattr(
        cli,
        "credential_backend_for_storage",
        lambda storage, *, vault_path=None, vault_min_passphrase_length=12: (_ for _ in ()).throw(
            cli.CredentialError(
                "No supported OS keyring is available. Install `imapledger[keyring]` or use "
                "`imapledger auth set --storage vault`."
            )
        ),
    )
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("storage selection must precede prompts"))

    result = CliRunner().invoke(cli.app, ["auth", "set", "--storage", storage, "--config", str(config_path)])

    assert result.exit_code == 2
    assert "--storage vault" in result.output
    assert load_settings(config_path).imap.auth.source is AuthSource.PROMPT


def test_auth_status_keyring_unavailable_prints_safe_install_hint(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    _write_auth_config(config_path, AuthSource.KEYRING)
    monkeypatch.setattr(
        cli,
        "credential_status",
        lambda imap: CredentialStatus(
            AuthSource.KEYRING,
            None,
            backend_available=False,
            reason="keyring support is not installed",
        ),
    )
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("status must not prompt"))

    result = CliRunner().invoke(cli.app, ["auth", "status", "--verbose", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "configured source: keyring" in result.output
    assert "available: no" in result.output
    assert "reason: keyring support is not installed" in result.output
    assert "hint: pip install 'imapledger[keyring]'" in result.output
    assert "alternative: imapledger auth set --storage vault" in result.output


def test_auth_set_help_documents_storage_modes_and_replacement() -> None:
    result = CliRunner().invoke(cli.app, ["auth", "set", "--help"])

    assert result.exit_code == 0, result.output
    assert "auto (default)" in result.output
    assert "encrypted-file alias" in result.output
    assert "--replace" in result.output
