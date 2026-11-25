from __future__ import annotations

from typing import Any

import pytest
from pyjev.decisions import BundleDecision, ChoiceDecision, NoulDecision
from pyjev.results import BundleResult, ChoiceResult, NoulResult

from imapledger.config import ActionKind, MessageAction
from imapledger.message import MailMessage
from imapledger.rule_candidates import RuleCandidate, build_rule_candidates
from imapledger.rule_learning import (
    MIN_CANDIDATE_CONFIDENCE,
    MIN_GENERALIZATION_PROBABILITY,
    NONE_CANDIDATE_ID,
    learn_rule_proposal,
)
from imapledger.rules import RuleError, RuleMatch


class FakeJev:
    def __init__(self, selected: str, *, confidence: float = 0.96, safe: float = 0.98) -> None:
        self.selected = selected
        self.confidence = confidence
        self.safe = safe
        self.calls: list[tuple[object, dict[str, object]]] = []

    def evaluate(self, decision: object, *, state: dict[str, object]) -> BundleResult:
        self.calls.append((decision, state))
        assert isinstance(decision, BundleDecision)
        choice = decision.questions["candidate"]
        assert isinstance(choice, ChoiceDecision)
        probabilities = {option: 0.0 for option in choice.options}
        if self.selected in probabilities:
            probabilities[self.selected] = self.confidence
        answers = {
            "candidate": ChoiceResult(
                value=self.selected,
                confidence=self.confidence,
                probabilities=probabilities,
                model="choice-model",
                usage={},
                raw={},
                request_id="choice-request",
            ),
            "safe_to_generalize": NoulResult(
                value=self.safe,
                model="safety-model",
                usage={},
                raw={},
                request_id="safety-request",
            ),
        }
        return BundleResult(answers, model="bundle-model", usage={}, raw={}, request_id="request-test")


def _message(**values: Any) -> MailMessage:
    defaults: dict[str, Any] = {
        "uid": 43627,
        "subject": "Ihre E-Mail konnte nicht zugestellt werden",
        "sender": "Mailer Daemon <mailer-daemon@gmx.net>",
        "recipients": (),
        "date": "",
        "body": "SECRET BODY SHOULD NOT BE SENT",
        "from_display_name": "Mailer Daemon",
        "from_address": "mailer-daemon@gmx.net",
        "reply_to": "",
        "sender_header": "",
        "return_path": "",
        "list_id": "",
        "precedence": "",
        "auto_submitted": "",
    }
    defaults.update(values)
    return MailMessage(**defaults)


def _candidate(candidates: tuple[RuleCandidate, ...], candidate_id: str) -> RuleCandidate:
    return next(candidate for candidate in candidates if candidate.id == candidate_id)


def test_candidate_generation_uses_only_known_structured_fields() -> None:
    candidates = build_rule_candidates(
        _message(
            list_id="notices.example.org",
            return_path="bounce@example.org",
            auto_submitted="auto-replied",
        )
    )
    ids = {candidate.id for candidate in candidates}

    assert "from_address_exact" in ids
    assert "list_id_exact" in ids
    assert "return_path_address_exact" in ids
    assert "from_address_and_auto_submitted" in ids
    allowed_fields = {
        "from_address",
        "from_domain",
        "return_path",
        "return_path_domain",
        "list_id",
        "auto_submitted",
        "subject",
        "subject_prefix",
    }
    assert all(set(candidate.match.as_dict()) <= allowed_fields for candidate in candidates)
    assert all(candidate.id.isascii() for candidate in candidates)


def test_exact_sender_candidate_is_auto_safe_and_domain_candidate_is_not() -> None:
    candidates = build_rule_candidates(_message())

    assert _candidate(candidates, "from_address_exact").auto_safe
    assert not _candidate(candidates, "from_domain_exact").auto_safe


def test_jev_selects_only_supplied_candidate_ids_and_auto_proposal_is_typed() -> None:
    message = _message(body="BODY MUST NOT BE INCLUDED")
    candidates = build_rule_candidates(message)
    jev = FakeJev("from_address_exact")
    proposal = learn_rule_proposal(
        jev,
        message=message,
        candidates=candidates,
        requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )

    decision, state = jev.calls[0]
    assert isinstance(decision, BundleDecision)
    assert isinstance(decision.questions["candidate"], ChoiceDecision)
    assert isinstance(decision.questions["safe_to_generalize"], NoulDecision)
    candidate_choice = decision.questions["candidate"]
    assert isinstance(candidate_choice, ChoiceDecision)
    assert set(candidate_choice.options) == {candidate.id for candidate in candidates} | {NONE_CANDIDATE_ID}
    assert proposal.status == "auto"
    assert proposal.candidate == _candidate(candidates, "from_address_exact")
    assert proposal.candidate_confidence == 0.96
    assert proposal.safe_probability == 0.98
    assert proposal.model == "bundle-model"
    assert proposal.request_id == "request-test"
    assert "body" not in state["message"]
    assert "BODY MUST NOT BE INCLUDED" not in str(state)
    assert state["requested_action"] == {"kind": "move", "destination": "INBOX.Trash"}

    rule = proposal.to_rule(
        id="mailer-daemon-gmx-net",
        source_folders=("INBOX.Junk",),
        action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )
    assert rule.match == RuleMatch(from_address="mailer-daemon@gmx.net")
    assert rule.source_folders == ("INBOX.Junk",)


def test_low_candidate_confidence_requires_review() -> None:
    candidates = build_rule_candidates(_message())
    jev = FakeJev("from_address_exact", confidence=MIN_CANDIDATE_CONFIDENCE - 0.01)

    proposal = learn_rule_proposal(
        jev,
        message=_message(),
        candidates=candidates,
        requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )

    assert proposal.status == "review"


def test_low_generalization_probability_requires_review() -> None:
    candidates = build_rule_candidates(_message())
    jev = FakeJev("from_address_exact", safe=MIN_GENERALIZATION_PROBABILITY - 0.01)

    proposal = learn_rule_proposal(
        jev,
        message=_message(),
        candidates=candidates,
        requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )

    assert proposal.status == "review"


def test_domain_only_candidate_is_never_automatically_accepted() -> None:
    candidates = build_rule_candidates(_message())
    jev = FakeJev("from_domain_exact")

    proposal = learn_rule_proposal(
        jev,
        message=_message(),
        candidates=candidates,
        requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )

    assert proposal.status == "review"
    assert proposal.candidate is not None and not proposal.candidate.auto_safe


def test_none_candidate_means_no_safe_rule() -> None:
    candidates = build_rule_candidates(_message())
    jev = FakeJev(NONE_CANDIDATE_ID)

    proposal = learn_rule_proposal(
        jev,
        message=_message(),
        candidates=candidates,
        requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )

    assert proposal.status == "none"
    assert proposal.candidate is None


def test_unknown_model_candidate_is_rejected() -> None:
    candidates = build_rule_candidates(_message())
    jev = FakeJev("model-invented-expression")

    with pytest.raises(RuleError, match="unknown rule candidate"):
        learn_rule_proposal(
            jev,
            message=_message(),
            candidates=candidates,
            requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        )


def test_empty_candidate_set_does_not_call_jev() -> None:
    jev = FakeJev(NONE_CANDIDATE_ID)

    proposal = learn_rule_proposal(
        jev,
        message=_message(),
        candidates=(),
        requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )

    assert proposal.status == "none"
    assert jev.calls == []


def test_requested_destination_is_not_selected_by_jev() -> None:
    candidates = build_rule_candidates(_message())
    jev = FakeJev("from_address_exact")
    learn_rule_proposal(
        jev,
        message=_message(),
        candidates=candidates,
        requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )

    decision, state = jev.calls[0]
    assert isinstance(decision, BundleDecision)
    assert "destination" not in decision.questions["candidate"].options
    assert state["requested_action"]["destination"] == "INBOX.Trash"  # type: ignore[index]


def test_malformed_probability_distribution_is_rejected() -> None:
    candidates = build_rule_candidates(_message())

    class MalformedJev(FakeJev):
        def evaluate(self, decision: object, *, state: dict[str, object]) -> BundleResult:
            result = super().evaluate(decision, state=state)
            result.answers["candidate"].probabilities.pop(NONE_CANDIDATE_ID)  # type: ignore[union-attr]
            return result

    with pytest.raises(RuleError, match="incomplete candidate probability"):
        learn_rule_proposal(
            MalformedJev("from_address_exact"),
            message=_message(),
            candidates=candidates,
            requested_action=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        )
