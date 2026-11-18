from __future__ import annotations

import pytest

from imapledger.classifier import SemanticSpamSignals
from imapledger.evidence import build_message_evidence
from imapledger.message import MailMessage
from imapledger.policy import SpamPolicy, SpamVerdict


def _signals(**overrides: float) -> SemanticSpamSignals:
    values = {
        "unsolicited_bulk": 0.10,
        "phishing_or_scam": 0.10,
        "identity_deception": 0.10,
        "legitimate_expected": 0.10,
        "delete_safe": 0.10,
    }
    values.update(overrides)
    return SemanticSpamSignals(**values)


def _evidence(
    *,
    sender: str = "sender@example.org",
    display_name: str = "sender",
    subject: str = "subject",
    spam_flag: str = "",
):
    message = MailMessage(
        uid=1,
        subject=subject,
        sender=f"{display_name} <{sender}>",
        recipients=(),
        date="",
        body="body",
        from_display_name=display_name,
        from_address=sender,
        x_spam_flag=spam_flag,
    )
    return build_message_evidence(message, trusted_provider_headers=("X-Spam-Flag",))


def test_strong_legitimate_evidence_vetoes_even_otherwise_deletable_signals() -> None:
    decision = SpamPolicy().decide(
        _signals(phishing_or_scam=0.99, delete_safe=0.99, legitimate_expected=0.80), _evidence()
    )

    assert decision.verdict is SpamVerdict.KEEP
    assert decision.reasons == ("strong-legitimate-or-expected",)


def test_high_phishing_signal_authorizes_delete_at_its_named_threshold() -> None:
    decision = SpamPolicy().decide(_signals(phishing_or_scam=0.90), _evidence())

    assert decision.verdict is SpamVerdict.DELETE
    assert decision.reasons == ("strong-phishing-or-scam",)


def test_identity_deception_requires_delete_safe_corroboration() -> None:
    policy = SpamPolicy()

    insufficient = policy.decide(_signals(identity_deception=0.99, delete_safe=0.79), _evidence())
    supported = policy.decide(_signals(identity_deception=0.90, delete_safe=0.80), _evidence())

    assert insufficient.verdict is SpamVerdict.REVIEW
    assert supported.verdict is SpamVerdict.DELETE
    assert "identity-deception" in supported.reasons


def test_bulk_evidence_requires_delete_safe_support() -> None:
    policy = SpamPolicy()

    insufficient = policy.decide(_signals(unsolicited_bulk=0.99, delete_safe=0.87), _evidence())
    supported = policy.decide(_signals(unsolicited_bulk=0.92, delete_safe=0.88), _evidence())

    assert insufficient.verdict is SpamVerdict.REVIEW
    assert supported.verdict is SpamVerdict.DELETE
    assert "unsolicited-bulk" in supported.reasons


def test_trusted_provider_junk_requires_semantic_support_and_low_legitimacy() -> None:
    evidence = _evidence(spam_flag="YES")
    policy = SpamPolicy()

    marker_only = policy.decide(_signals(), evidence)
    supported = policy.decide(_signals(delete_safe=0.80, legitimate_expected=0.49), evidence)

    assert evidence.provider.trusted_spam is True
    assert marker_only.verdict is SpamVerdict.REVIEW
    assert supported.verdict is SpamVerdict.DELETE


def test_provider_and_subject_markers_alone_are_review_not_delete() -> None:
    provider = SpamPolicy().decide(_signals(), _evidence(spam_flag="YES"))
    subject = SpamPolicy().decide(_signals(), _evidence(subject="***SPAM*** subject"))

    assert provider.verdict is SpamVerdict.REVIEW
    assert subject.verdict is SpamVerdict.REVIEW
    assert "needs-corroboration" in provider.reasons[0]


def test_high_delete_safe_does_not_override_legitimacy_or_uncertainty() -> None:
    policy = SpamPolicy()

    legitimate = policy.decide(_signals(delete_safe=0.99, legitimate_expected=0.90), _evidence())
    uncertain = policy.decide(_signals(delete_safe=0.99), _evidence())

    assert legitimate.verdict is SpamVerdict.KEEP
    assert uncertain.verdict is SpamVerdict.REVIEW


@pytest.mark.parametrize(
    ("display_name", "sender", "signals", "expected"),
    [
        (
            "Trezor",
            "noreply@performology.com",
            _signals(identity_deception=0.95, delete_safe=0.90),
            SpamVerdict.DELETE,
        ),
        (
            "Ꮮеⅾger",
            "support@agentur-plietsch.de",
            _signals(identity_deception=0.95, delete_safe=0.90),
            SpamVerdict.DELETE,
        ),
        (
            "Finanzexperte",
            "mail@mailings.finance1-online.de",
            _signals(unsolicited_bulk=0.95, delete_safe=0.90),
            SpamVerdict.DELETE,
        ),
    ],
)
def test_visible_brief_examples_use_general_evidence_rules(display_name, sender, signals, expected) -> None:
    evidence = _evidence(display_name=display_name, sender=sender)

    assert SpamPolicy().decide(signals, evidence).verdict is expected


def test_invalid_policy_threshold_or_signal_fails_closed() -> None:
    with pytest.raises(ValueError, match="policy"):
        SpamPolicy(phishing_delete_at=1.1)
    with pytest.raises(ValueError, match="finite probability"):
        SpamPolicy().decide(_signals(delete_safe=float("nan")), _evidence())
