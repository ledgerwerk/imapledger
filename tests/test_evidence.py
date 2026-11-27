from __future__ import annotations

from imapledger.evidence import (
    MAX_LINK_DOMAINS,
    MailboxContext,
    build_jev_state,
    build_message_evidence,
    normalize_domain,
    organizational_domain,
)
from imapledger.message import MailMessage


def _message(**overrides: object) -> MailMessage:
    values: dict[str, object] = {
        "uid": 7,
        "subject": "subject",
        "sender": "sender@example.org",
        "recipients": (),
        "date": "",
        "body": "body",
        "from_display_name": "sender",
        "from_address": "sender@example.org",
    }
    values.update(overrides)
    return MailMessage(**values)


def test_domain_normalization_and_public_suffix_organizational_domains() -> None:
    assert normalize_domain("News.Example.CO.UK.") == "news.example.co.uk"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"
    assert organizational_domain("mail.one.example.co.uk") == "example.co.uk"
    assert organizational_domain("mail.two.example.co.uk") == "example.co.uk"


def test_evidence_extracts_sender_relationships_and_mixed_script_hints() -> None:
    message = _message(
        from_display_name="Ꮮеⅾger",
        from_address="support@agentur-plietsch.de",
        reply_to="reply@agentur-plietsch.de",
        sender_header="relay@sender.example",
        return_path="bounce@agentur-plietsch.de",
        message_id="<id@agentur-plietsch.de>",
    )

    evidence = build_message_evidence(message)

    assert evidence.from_address.display_name == "Ꮮеⅾger"
    assert evidence.from_address.domain == "agentur-plietsch.de"
    assert evidence.from_vs_reply_to_same_org_domain is True
    assert evidence.from_vs_return_path_same_org_domain is True
    assert evidence.from_vs_message_id_same_org_domain is True
    assert evidence.display_name_non_ascii is True
    assert evidence.display_name_mixed_scripts is True
    assert evidence.authentication.trusted is False
    assert evidence.authentication.spf is None


def test_organizational_comparison_respects_multi_label_public_suffixes() -> None:
    message = _message(
        from_address="sender@mail.example.co.uk",
        reply_to="reply@other.example.co.uk",
        return_path="bounce@different.co.uk",
        message_id="<id@mx.example.co.uk>",
    )

    evidence = build_message_evidence(message)

    assert evidence.from_address.organizational_domain == "example.co.uk"
    assert evidence.from_vs_reply_to_same_org_domain is True
    assert evidence.from_vs_return_path_same_org_domain is False
    assert evidence.from_vs_message_id_same_org_domain is True


def test_provider_and_mailing_list_headers_are_evidence_not_allow_signals() -> None:
    message = _message(
        subject="***SPAM*** newsletter",
        list_id="news.example",
        list_unsubscribe=("<https://example.org/unsubscribe>",),
        list_unsubscribe_post=("List-Unsubscribe=One-Click",),
        precedence="bulk",
        auto_submitted="auto-generated",
        x_spam_flag="YES",
        x_spam_status="Yes, score=8.2",
        x_spam_score="8.2",
    )

    evidence = build_message_evidence(message)
    trusted = build_message_evidence(message, trusted_provider_headers=("X-Spam-Flag",))

    assert evidence.mailing_list.list_id == "news.example"
    assert evidence.mailing_list.unsubscribe_present is True
    assert evidence.mailing_list.one_click_unsubscribe is True
    assert evidence.provider.spam_marker is True
    assert evidence.provider.subject_spam_marker is True
    assert evidence.provider.trusted_spam is False
    assert trusted.provider.trusted_spam is True


def test_untrusted_authentication_headers_are_not_exposed_or_used() -> None:
    message = _message(
        authentication_results_raw=("mx.attacker.example; spf=pass smtp.mailfrom=attacker.example",),
        received_spf_raw=("pass",),
        arc_authentication_results_raw=("i=1; mx.attacker.example; arc=pass",),
    )

    evidence = build_message_evidence(message)
    state = build_jev_state(evidence, message)

    assert evidence.authentication.trusted is False
    assert evidence.authentication.spf is None
    assert evidence.authentication.arc is None
    assert state["authentication"]["trusted"] is False
    assert "mx.attacker.example" not in repr(state)
    assert "uid" not in repr(state)


def test_configured_authserv_id_parses_trusted_authentication_evidence() -> None:
    message = _message(
        authentication_results_raw=(
            "mx.example; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; "
            "dmarc=pass header.from=example.org; arc=pass",
        )
    )

    evidence = build_message_evidence(message, trusted_authserv_ids=("mx.example",))

    assert evidence.authentication.trusted is True
    assert evidence.authentication.authserv_id == "mx.example"
    assert evidence.authentication.spf == "pass"
    assert evidence.authentication.spf_domain == "sender.example"
    assert evidence.authentication.dkim[0].domain == "sender.example"
    assert evidence.authentication.dmarc == "pass"
    assert evidence.authentication.dmarc_from_domain == "example.org"
    assert evidence.authentication.arc == "pass"


def test_links_are_normalized_deduplicated_and_bounded_without_urls() -> None:
    domains = " ".join(f"https://site{index}.example/path?token=secret" for index in range(MAX_LINK_DOMAINS + 5))
    message = _message(
        from_address="sender@example.org",
        body=domains + " mailto:help@example.org https://site0.example/again",
    )

    evidence = build_message_evidence(message)
    state = build_jev_state(evidence, message, context=MailboxContext(source_folder="INBOX.Junk"))

    assert evidence.links.distinct_domain_count == MAX_LINK_DOMAINS
    assert len(evidence.links.domains) == MAX_LINK_DOMAINS
    assert evidence.links.from_domain_matches_any is False
    assert "token" not in repr(state)
    assert "/path" not in repr(state)
    assert "source_folder" in state["mailbox_context"]


def test_idn_domain_and_unicode_sender_facts_are_preserved() -> None:
    message = _message(
        from_display_name="Ledger",
        from_address="support@bücher.example",
        sender="Ledger <support@bücher.example>",
    )

    evidence = build_message_evidence(message)

    assert evidence.from_address.domain == "xn--bcher-kva.example"
    assert evidence.domain_is_idn is True
