from __future__ import annotations

from pathlib import Path

import pytest

from imapledger.application.browsing import ReviewOperation, ReviewRequest
from imapledger.application.rules import RuleLearningOperation, RuleMigrationOperation
from imapledger.application.state import StateOperation, StateResetRequest
from imapledger.classification_state import SpamOutcome, keyword_for_outcome
from imapledger.config import ImapSettings, Settings, SpamSettings
from imapledger.mailbox import MessageSort
from imapledger.message import MailMessage, MailSummary
from imapledger.routing_config import RoutingConfigError, write_routing_rules
from imapledger.routing_models import RoutingRule, RuleType
from imapledger.routing_models import RuleSet as RoutingRuleSet
from imapledger.routing_rule_service import RoutingRuleService
from imapledger.rule_candidates import build_rule_candidates
from imapledger.rule_learning import RuleProposal
from imapledger.rules import RuleMatch


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("Spam",)),
    )


class _ReviewMailbox:
    def __init__(self, *, folder: str, **kwargs: object) -> None:
        self.folder = folder

    def __enter__(self) -> _ReviewMailbox:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def search_keyword(self, keyword: str) -> set[int]:
        assert keyword
        return {1, 2, 3, 4, 5, 6, 7}

    def fetch_headers(self, uid: int) -> MailSummary:
        return MailSummary(uid, "sender", f"subject {uid}", "date", str(uid), None, frozenset(), None)


def test_review_operation_returns_sorted_page_and_total() -> None:
    operation = ReviewOperation(_settings(), mailbox_factory=_ReviewMailbox)

    page = operation.run(
        ReviewRequest(folder="Spam", limit=2, offset=2, sort=MessageSort.OLDEST),
        password="secret",
    )

    assert page.total == 7
    assert [summary.uid for _, summary in page.items] == [3, 4]
    assert page.has_previous is True
    assert page.has_next is True
    assert page.errors == ()


class _StateMailbox:
    flags: dict[int, list[str]] = {4: [keyword_for_outcome(SpamOutcome.SPAM)]}
    writable_seen: list[bool] = []

    def __init__(self, *, writable: bool, **kwargs: object) -> None:
        self.writable_seen.append(writable)

    def __enter__(self) -> _StateMailbox:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get_flags(self, uid: int) -> list[str]:
        return self.flags.get(uid, []).copy()

    def search_keyword(self, keyword: str) -> set[int]:
        return {uid for uid, flags in self.flags.items() if keyword in flags}

    def remove_keyword(self, uid: int, keyword: str) -> None:
        self.flags[uid].remove(keyword)


def test_state_reset_preview_is_read_only_and_apply_removes_owned_markers() -> None:
    _StateMailbox.flags = {4: [keyword_for_outcome(SpamOutcome.SPAM)]}
    _StateMailbox.writable_seen = []
    operation = StateOperation(_settings(), mailbox_factory=_StateMailbox)
    preview_request = StateResetRequest(folder="Spam", uid=4)

    preview = operation.reset_folder("Spam", preview_request, password="secret")
    applied = operation.reset_folder("Spam", StateResetRequest(folder="Spam", uid=4, apply=True), password="secret")

    assert preview.targeted_uids == (4,)
    assert preview.marker_count == 1
    assert preview.apply is False
    assert applied.apply is True
    assert _StateMailbox.flags[4] == []
    assert _StateMailbox.writable_seen == [False, True]


def test_state_reset_requires_explicit_unbounded_scope() -> None:
    operation = StateOperation(_settings())

    with pytest.raises(ValueError, match="unbounded reset"):
        operation.reset_folders(StateResetRequest(folder="Spam"))
    with pytest.raises(ValueError, match="requires --all"):
        operation.reset_folders(StateResetRequest(all_folders=True))
    assert operation.reset_folders(StateResetRequest(all_folders=True, reset_all=True)) == ("Spam",)


def test_rule_migration_apply_uses_preview_and_rejects_stale_file(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    source = (
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "github"\n'
        'enabled = true\nsource_folders = ["Spam"]\naction = "move"\n'
        'destination = "Archive"\nmatch = { from_domain = "github.com" }\n'
    )
    path.write_text(source, encoding="utf-8")
    operation = RuleMigrationOperation(path)
    preview = operation.preview()
    assert path.read_text(encoding="utf-8") == source

    path.write_text(source + "\n# changed\n", encoding="utf-8")
    with pytest.raises(RoutingConfigError, match="changed after migration preview"):
        operation.apply(preview)

    fresh_preview = operation.preview()
    applied = operation.apply(fresh_preview)
    assert applied.applied is True
    assert applied.rules.rules[0].id == "github"
    assert "schema = 2" in path.read_text(encoding="utf-8")


def test_rule_learning_saves_only_against_unchanged_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    message = MailMessage(
        uid=12,
        subject="delivery failure",
        sender="Mailer Daemon <mailer-daemon@example.net>",
        recipients=(),
        date="",
        body="not used",
        from_display_name="Mailer Daemon",
        from_address="mailer-daemon@example.net",
        reply_to="",
        sender_header="",
        return_path="",
        list_id="",
        precedence="",
        auto_submitted="",
    )
    candidate = next(item for item in build_rule_candidates(message) if item.id == "from_address_exact")
    proposal = RuleProposal(candidate, "auto", 0.96, 0.98, "model", "request")
    monkeypatch.setattr("imapledger.application.rules.learn_rule_proposal", lambda *args, **kwargs: proposal)

    class _Jev:
        def __enter__(self) -> _Jev:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    path = tmp_path / "rules.toml"
    write_routing_rules(RoutingRuleSet(), path)
    service = RoutingRuleService(path)
    operation = RuleLearningOperation()
    preview = operation.propose(
        message,
        folder="Spam",
        destination="Archive",
        existing_rules=service.load(),
        jev_factory=_Jev,
    )
    assert preview.rule is not None
    assert preview.rule.destination == "Archive"
    assert preview.rule.source_folders == ("Spam",)

    second_rule = RoutingRule(
        id="other",
        enabled=True,
        type=RuleType.HEADER,
        destination="Archive",
        match=RuleMatch(subject="urgent"),
        source_folders=("Spam",),
    )
    service.add(second_rule)
    with pytest.raises(RoutingConfigError, match="rules changed after proposal"):
        operation.save(preview, service)
    assert service.load().rules == (second_rule,)
