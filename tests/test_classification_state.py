import pytest

from imapledger.classification_state import (
    OUTCOME_KEYWORDS,
    ClassificationStateBackend,
    ClassificationStateConflict,
    SpamOutcome,
    all_state_keywords,
    keyword_for_outcome,
    outcome_from_flags,
    validate_state_flags,
)


def test_keywords_are_fixed_and_ordered_by_outcome() -> None:
    assert all_state_keywords() == (
        "imapledger-v1-spam",
        "imapledger-v1-notspam",
        "imapledger-v1-review",
    )
    assert {outcome: keyword_for_outcome(outcome) for outcome in SpamOutcome} == OUTCOME_KEYWORDS
    assert ClassificationStateBackend.NONE.value == "none"
    assert ClassificationStateBackend.IMAP_KEYWORDS.value == "imap-keywords"


@pytest.mark.parametrize(
    ("outcome", "keyword"),
    [
        (SpamOutcome.SPAM, "imapledger-v1-spam"),
        (SpamOutcome.NOT_SPAM, "imapledger-v1-notspam"),
        (SpamOutcome.REVIEW, "imapledger-v1-review"),
    ],
)
def test_state_flags_are_case_insensitive_for_bytes_and_strings(outcome, keyword) -> None:
    assert outcome_from_flags([keyword.upper()]) is outcome
    assert outcome_from_flags([keyword.upper().encode()]) is outcome
    assert validate_state_flags([keyword.upper()]).keywords == frozenset({keyword})


def test_unmarked_message_has_no_state() -> None:
    state = validate_state_flags([b"\\Seen", b"$NotJunk"])

    assert state.outcome is None
    assert state.keywords == frozenset()
    assert outcome_from_flags([]) is None


def test_duplicate_case_variants_of_same_marker_are_not_conflicting() -> None:
    assert outcome_from_flags([b"imapledger-v1-review", "IMAPLEDGER-V1-REVIEW"]) is SpamOutcome.REVIEW


def test_multiple_outcome_markers_raise_explicit_conflict() -> None:
    with pytest.raises(ClassificationStateConflict, match="multiple imapledger classification state keywords") as error:
        validate_state_flags(["imapledger-v1-review", b"imapledger-v1-notspam"])

    assert error.value.keywords == ("imapledger-v1-notspam", "imapledger-v1-review")
