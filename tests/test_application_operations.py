from __future__ import annotations

from imapledger.application.doctor import DoctorOperation, DoctorRequest
from imapledger.application.progress import ProgressOperation
from imapledger.config import ImapSettings, Settings
from imapledger.preflight import SourcePreflightResult
from imapledger.progress_store import ProgressStore, account_identity_key


def _settings() -> Settings:
    return Settings(imap=ImapSettings(host="imap.example.org", username="user@example.org"))


def test_progress_operation_queries_errors_and_resets_exact_folder(tmp_path) -> None:
    settings = _settings()
    store = ProgressStore(tmp_path / "progress.sqlite3")
    run = store.begin_run(
        account_key=account_identity_key(settings),
        source_folder="INBOX",
        uidvalidity=42,
        high_watermark_uid=12,
        rules_fingerprint="fingerprint-a",
        mode="full",
        rule_scope=None,
        sort_direction="oldest",
    )
    store.record_result(run.id, uid=9, outcome="error", error_code="RuntimeError")
    operation = ProgressOperation(settings, store.path)

    runs = operation.list_runs(folder="INBOX")
    assert [item.id for item in runs] == [run.id]
    assert operation.latest_run("INBOX").id == run.id
    assert operation.latest_run_with_errors("INBOX").id == run.id
    assert operation.errors(run.id)[0].uid == 9
    assert operation.reset_folder("INBOX") == 1
    assert operation.list_runs(folder="INBOX") == ()


def test_doctor_operation_delegates_read_only_preflight(monkeypatch) -> None:
    settings = _settings()
    mailbox_factory = object()
    events: list[str] = []
    observed: dict[str, object] = {}
    result = SourcePreflightResult(
        folder="Spam",
        opened=True,
        probe=None,
        capabilities=frozenset(),
        missing_capabilities=(),
        destinations=(("Archive", True),),
        errors=(),
    )

    def fake_preflight(actual_settings, folder, **kwargs):
        observed.update(settings=actual_settings, folder=folder, **kwargs)
        kwargs["event_callback"]("connected")
        return result

    monkeypatch.setattr("imapledger.application.doctor.preflight_source", fake_preflight)
    operation = DoctorOperation(settings, mailbox_factory=mailbox_factory)
    request = DoctorRequest(
        folder="Spam",
        destinations=("Archive",),
        requires_delete=True,
        deep_probe=True,
    )
    actual = operation.run(request, password="secret", event_callback=events.append)

    assert actual is result
    assert observed["settings"] is settings
    assert observed["folder"] == "Spam"
    assert observed["password"] == "secret"
    assert observed["destinations"] == ("Archive",)
    assert observed["requires_delete"] is True
    assert observed["deep_probe"] is True
    assert observed["mailbox_factory"] is mailbox_factory
    assert events == ["connected"]
