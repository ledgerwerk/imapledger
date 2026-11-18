from contextlib import AbstractContextManager

from imapledger.classifier import SemanticSpamSignals, SpamAssessment
from imapledger.cleaner import VERDICT_OUTCOME, SpamCleaner, SpamOutcome
from imapledger.config import ActionKind, MessageAction, SpamActions
from imapledger.evidence import build_message_evidence
from imapledger.mailbox import (
    DeleteResult,
    ImapOperationError,
    MailboxItem,
    MessageSelection,
    MessageSort,
    MoveResult,
    PartialDeleteError,
    PartialMoveError,
)
from imapledger.message import MailMessage
from imapledger.policy import SpamVerdict
from imapledger.rules import MailRule, RuleMatch, RuleSet


class FakeMailbox(AbstractContextManager):
    folder = "Spam"

    def __init__(self, *, writable: bool, events=None):
        self.writable = writable
        self.deleted = []
        self.moved = []
        self.events = events
        self.count_selections = []
        self.iter_selections = []
        self.items = [
            MailboxItem(uid=1, message=MailMessage(1, "phish", "a@example.org", (), "", "buy now")),
            MailboxItem(uid=2, message=MailMessage(2, "real", "b@example.org", (), "", "hello")),
            MailboxItem(uid=3, skip_reason="too large"),
        ]

    def selected_count(self, selection):
        self.count_selections.append(selection)
        return len(self.items)

    def iter_messages(self, selection=None):
        self.iter_selections.append(selection)
        yield from self.items

    def move_uid(self, uid, destination):
        return self.move_uids((uid,), destination)

    def move_uids(self, uids, destination):
        self.moved.append((tuple(uids), destination))
        if self.events is not None:
            self.events.append(f"move:{uids[0]}:{destination}")
        return MoveResult(moved=tuple(uids), destination=destination)

    def delete_uid(self, uid):
        return self.delete_uids((uid,))

    def delete_uids(self, uids):
        self.deleted.extend(uids)
        return DeleteResult(deleted=tuple(uids))

    def __exit__(self, *args):
        return None


def _signals(uid: int) -> SemanticSpamSignals:
    if uid in {1, 4}:
        return SemanticSpamSignals(0.10, 0.99, 0.10, 0.10, 0.10)
    if uid == 2:
        return SemanticSpamSignals(0.10, 0.10, 0.10, 0.90, 0.99)
    return SemanticSpamSignals(0.10, 0.10, 0.10, 0.10, 0.10)


def _assessment(message: MailMessage) -> SpamAssessment:
    return SpamAssessment(
        signals=_signals(message.uid),
        evidence=build_message_evidence(message),
        model="model-test",
        request_id=f"request-{message.uid}",
    )


class FakeClassifier:
    def __init__(self, events=None):
        self.events = events

    def assess(self, message):
        if self.events is not None:
            self.events.append(f"classify:{message.uid}")
        return _assessment(message)


def test_verdicts_map_to_routing_outcomes_without_changing_policy_verdicts():
    assert VERDICT_OUTCOME == {
        SpamVerdict.DELETE: SpamOutcome.SPAM,
        SpamVerdict.KEEP: SpamOutcome.NOT_SPAM,
        SpamVerdict.REVIEW: SpamOutcome.REVIEW,
    }


def test_dry_run_never_mutates_and_records_configured_actions():
    mailbox = FakeMailbox(writable=False)
    actions = SpamActions(
        spam=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        not_spam=MessageAction(ActionKind.MOVE, "INBOX.NotSpam"),
    )

    report = SpamCleaner(mailbox, FakeClassifier(), actions=actions).run(apply=False)

    assert report.scanned == 3
    assert report.spam == 1
    assert report.not_spam == report.kept == 1
    assert report.review == 0
    assert report.skipped == 1
    assert report.deleted == report.moved == 0
    assert mailbox.deleted == []
    assert mailbox.moved == []
    assert report.results[0].outcome is SpamOutcome.SPAM
    assert report.results[0].action == MessageAction(ActionKind.MOVE, "INBOX.Trash")
    assert report.results[0].action_applied is False
    assert report.results[2].action.action is ActionKind.KEEP
    assert report.results[2].detail == "too large"
    assert report.results[0].verdict is SpamVerdict.DELETE
    assert report.results[0].signals.phishing_or_scam == 0.99
    assert report.results[0].model == "model-test"
    assert report.results[0].request_id == "request-1"


def test_apply_routes_spam_and_not_spam_during_iteration():
    mailbox = FakeMailbox(writable=True)
    actions = SpamActions(
        spam=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        not_spam=MessageAction(ActionKind.MOVE, "INBOX.NotSpam"),
    )

    report = SpamCleaner(mailbox, FakeClassifier(), actions=actions).run(apply=True)

    assert mailbox.moved == [((1,), "INBOX.Trash"), ((2,), "INBOX.NotSpam")]
    assert mailbox.deleted == []
    assert report.moved == 2
    assert report.deleted == 0
    assert [row.action_applied for row in report.results] == [True, True, False]


def test_review_can_be_moved_using_review_action():
    class ReviewClassifier:
        def assess(self, message):
            return SpamAssessment(
                signals=SemanticSpamSignals(0.1, 0.1, 0.1, 0.1, 0.99),
                evidence=build_message_evidence(message),
            )

    mailbox = FakeMailbox(writable=True)
    actions = SpamActions(review=MessageAction(ActionKind.MOVE, "INBOX.Review"))

    report = SpamCleaner(mailbox, ReviewClassifier(), actions=actions).run(apply=True)

    assert report.review == 2
    assert mailbox.moved == [((1,), "INBOX.Review"), ((2,), "INBOX.Review")]
    assert all(row.outcome is SpamOutcome.REVIEW for row in report.results[:2])



def test_rule_match_bypasses_classifier_and_moves_immediately_before_next_message():
    events = []
    mailbox = FakeMailbox(writable=True, events=events)
    mailbox.items[0] = MailboxItem(
        uid=1,
        message=MailMessage(1, "delivery failure", "a@example.org", (), "", "body", from_address="a@example.org"),
    )
    rule = MailRule(
        id="sender-route",
        enabled=True,
        source_folders=("Spam",),
        action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        match=RuleMatch(from_address="a@example.org"),
    )
    callbacks = []

    report = SpamCleaner(
        mailbox,
        FakeClassifier(events),
        rules=RuleSet((rule,)),
    ).run(apply=True, on_result=lambda row, position, total: (callbacks.append(row), events.append(f"row:{row.uid}")))

    assert events == ["move:1:INBOX.Trash", "row:1", "classify:2", "row:2", "row:3"]
    assert mailbox.moved == [((1,), "INBOX.Trash")]
    assert report.rule_matches == 1
    assert report.spam == 0
    assert report.results[0].matched_rule_id == "sender-route"
    assert report.results[0].decision_source == "rule"
    assert report.results[0].verdict is None
    assert report.results[0].signals is None
    assert report.results[0].outcome is None
    assert report.results[0].action_applied
    assert callbacks == report.results


def test_rule_dry_run_does_not_mutate_and_nonmatches_still_use_classifier():
    events = []
    mailbox = FakeMailbox(writable=False, events=events)
    mailbox.items[0] = MailboxItem(
        uid=1,
        message=MailMessage(1, "delivery failure", "a@example.org", (), "", "body", from_address="a@example.org"),
    )
    rule = MailRule(
        id="sender-route",
        enabled=True,
        source_folders=("Spam",),
        action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        match=RuleMatch(from_address="a@example.org"),
    )

    report = SpamCleaner(mailbox, FakeClassifier(events), rules=RuleSet((rule,))).run(apply=False)

    assert events == ["classify:2"]
    assert mailbox.moved == []
    assert report.rule_matches == 1
    assert report.moved == 0
    assert report.results[0].matched_rule_id == "sender-route"
    assert report.results[0].action_applied is False
    assert report.results[1].decision_source == "spam"


def test_first_matching_rule_wins():
    mailbox = FakeMailbox(writable=True)
    mailbox.items[0] = MailboxItem(
        uid=1,
        message=MailMessage(1, "delivery failure", "a@example.org", (), "", "body", from_address="a@example.org"),
    )
    rules = RuleSet(
        (
            MailRule(
                "first-rule",
                True,
                ("Spam",),
                MessageAction(ActionKind.KEEP),
                RuleMatch(from_address="a@example.org"),
            ),
            MailRule(
                "second-rule",
                True,
                ("Spam",),
                MessageAction(ActionKind.MOVE, "INBOX.Trash"),
                RuleMatch(from_address="a@example.org"),
            ),
        )
    )

    report = SpamCleaner(mailbox, FakeClassifier(), rules=rules).run(apply=True)

    assert report.results[0].matched_rule_id == "first-rule"
    assert report.results[0].action.action is ActionKind.KEEP
    assert mailbox.moved == []
    assert report.results[0].outcome is None


def test_rule_matcher_error_fails_closed():
    class BrokenRules:
        def first_match(self, folder, message):
            raise RuntimeError("private message contents")

    mailbox = FakeMailbox(writable=True)
    report = SpamCleaner(mailbox, FakeClassifier(), rules=BrokenRules()).run(apply=True)  # type: ignore[arg-type]

    assert report.results[0].status == "error"
    assert report.results[0].decision_source == "error"
    assert report.results[0].action.action is ActionKind.KEEP
    assert report.results[0].detail == "RuntimeError: rule evaluation failed"
    assert mailbox.deleted == []
    assert mailbox.moved == []

def test_result_callback_fires_after_each_action_and_forwards_selection():
    events = []
    mailbox = FakeMailbox(writable=True, events=events)
    mailbox.items.append(MailboxItem(uid=4, message=MailMessage(4, "spam", "c@example.org", (), "", "more spam")))
    selection = MessageSelection(limit=4, offset=1, sort=MessageSort.OLDEST)
    callbacks = []
    actions = SpamActions(
        spam=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        not_spam=MessageAction(ActionKind.MOVE, "INBOX.NotSpam"),
    )

    report = SpamCleaner(mailbox, FakeClassifier(events), actions=actions).run(
        apply=True,
        selection=selection,
        on_result=lambda row, position, total: (
            callbacks.append((row, position, total)),
            events.append(f"row:{row.uid}"),
        ),
    )

    assert [row for row, _, _ in callbacks] == report.results
    assert [(position, total) for _, position, total in callbacks] == [(1, 4), (2, 4), (3, 4), (4, 4)]
    assert [row.action_applied for row, _, _ in callbacks] == [True, True, False, True]
    assert mailbox.count_selections == [selection]
    assert mailbox.iter_selections == [selection]
    assert mailbox.count_selections[0] is selection
    assert mailbox.iter_selections[0] is selection
    assert events == [
        "classify:1",
        "move:1:INBOX.Trash",
        "row:1",
        "classify:2",
        "move:2:INBOX.NotSpam",
        "row:2",
        "row:3",
        "classify:4",
        "move:4:INBOX.Trash",
        "row:4",
    ]
    assert mailbox.moved == [
        ((1,), "INBOX.Trash"),
        ((2,), "INBOX.NotSpam"),
        ((4,), "INBOX.Trash"),
    ]


def test_apply_deletes_only_configured_spam_action_uids():
    mailbox = FakeMailbox(writable=True)

    report = SpamCleaner(mailbox, FakeClassifier()).run(apply=True)

    assert mailbox.deleted == [1]
    assert report.deleted == 1
    assert report.not_spam == 1
    assert report.skipped == 1
    assert report.results[0].action_applied is True
    assert report.results[0].deleted is True


class FailingClassifier:
    def assess(self, message):
        raise RuntimeError("model error containing private message content")


def test_classifier_error_fails_closed_and_skip_error_never_mutate():
    mailbox = FakeMailbox(writable=True)
    report = SpamCleaner(mailbox, FailingClassifier()).run(apply=True)

    error_row = report.results[0]
    assert error_row.status == "error"
    assert error_row.inclination == "ERROR / KEEP"
    assert error_row.action.action is ActionKind.KEEP
    assert error_row.detail == "RuntimeError: classification evaluation failed"
    assert mailbox.deleted == []
    assert mailbox.moved == []
    assert report.results[2].action.action is ActionKind.KEEP


class PartialFakeMailbox(FakeMailbox):
    def __init__(self, *, writable: bool, events=None):
        super().__init__(writable=writable, events=events)
        self.items.extend(
            [
                MailboxItem(uid=4, message=MailMessage(4, "phish", "c@example.org", (), "", "spam")),
                MailboxItem(uid=5, message=MailMessage(5, "later", "d@example.org", (), "", "spam")),
            ]
        )

    def move_uids(self, uids, destination):
        uids = tuple(uids)
        self.moved.append((uids, destination))
        if self.events is not None:
            self.events.append(f"move:{uids[0]}:{destination}")
        if uids == (4,):
            failure = ImapOperationError(
                operation="imap_uid_move",
                message="UID MOVE failed",
                folder="Spam",
                uids=uids,
                batch=1,
                batch_count=1,
                cause_type="RuntimeError",
            )
            raise PartialMoveError(moved=(), pending=uids, destination=destination, failure=failure) from failure
        return MoveResult(moved=uids, destination=destination)


def test_partial_move_reports_failing_row_and_stops_classification_and_mutation():
    events = []
    mailbox = PartialFakeMailbox(writable=True, events=events)
    actions = SpamActions(
        spam=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        not_spam=MessageAction(ActionKind.MOVE, "INBOX.NotSpam"),
    )
    callbacks = []

    report = SpamCleaner(mailbox, FakeClassifier(events), actions=actions).run(
        apply=True,
        on_result=lambda row, position, total: (callbacks.append(row), events.append(f"row:{row.uid}")),
    )

    rows = {row.uid: row for row in report.results}
    assert report.partial_move_error is not None
    assert report.moved == 2
    assert report.scanned == 4
    assert [row.uid for row in callbacks] == [1, 2, 3, 4]
    assert rows[1].action_applied is True
    assert rows[2].action_applied is True
    assert rows[4].action_applied is False
    assert rows[4].detail == "Move was not confirmed; see the operation error."
    assert 5 not in rows
    assert mailbox.moved == [
        ((1,), "INBOX.Trash"),
        ((2,), "INBOX.NotSpam"),
        ((4,), "INBOX.Trash"),
    ]
    assert mailbox.deleted == []
    assert events == [
        "classify:1",
        "move:1:INBOX.Trash",
        "row:1",
        "classify:2",
        "move:2:INBOX.NotSpam",
        "row:2",
        "row:3",
        "classify:4",
        "move:4:INBOX.Trash",
        "row:4",
    ]


def test_partial_delete_marks_only_confirmed_uids():
    class PartialDeleteMailbox(FakeMailbox):
        def delete_uids(self, uids):
            uids = tuple(uids)
            if uids == (1,):
                self.deleted.extend(uids)
                return DeleteResult(deleted=uids)
            failure = ImapOperationError(
                operation="imap_uid_expunge",
                message="UID EXPUNGE failed",
                folder="Spam",
                uids=uids,
                batch=1,
                batch_count=1,
            )
            raise PartialDeleteError(deleted=(), pending=uids, failure=failure) from failure

    mailbox = PartialDeleteMailbox(writable=True)
    mailbox.items.append(MailboxItem(uid=4, message=MailMessage(4, "phish", "c@example.org", (), "", "spam")))
    report = SpamCleaner(mailbox, FakeClassifier()).run(apply=True)

    rows = {row.uid: row for row in report.results}
    assert report.partial_delete_error is not None
    assert report.deleted == 1
    assert rows[1].deleted is True
    assert rows[4].deleted is False
    assert rows[4].detail == "Deletion was not confirmed; see the operation error."
    assert report.scanned == 4
