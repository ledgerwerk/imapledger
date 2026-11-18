from imapledger.message import parse_message


def test_parse_plain_text_ignores_attachment() -> None:
    raw = b"""From: sender@example.org\r
To: me@example.org\r
Subject: Test\r
MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=x\r
\r
--x\r
Content-Type: text/plain; charset=utf-8\r
\r
hello world\r
--x\r
Content-Type: text/plain; name=secret.txt\r
Content-Disposition: attachment; filename=secret.txt\r
\r
attachment text\r
--x--\r
"""
    msg = parse_message(7, raw, max_body_chars=100)
    assert msg.uid == 7
    assert msg.subject == "Test"
    assert msg.body == "hello world"
    assert "attachment text" not in msg.body



def test_html_only_message_has_visible_text_body() -> None:
    raw = b"""From: sender@example.org\r
Subject: HTML\r
Content-Type: text/html; charset=utf-8\r
\r
<html><body><p>Hello <b>friend</b></p><p>Welcome!</p></body></html>"""

    message = parse_message(8, raw, max_body_chars=100)

    assert message.body == "Hello friend Welcome!"


def test_plain_text_is_preferred_over_html() -> None:
    raw = b"""From: sender@example.org\r
MIME-Version: 1.0\r
Content-Type: multipart/alternative; boundary=x\r
\r
--x\r
Content-Type: text/plain; charset=utf-8\r
\r
Plain version\r
--x\r
Content-Type: text/html; charset=utf-8\r
\r
<p>HTML version</p>\r
--x--\r
"""

    message = parse_message(9, raw, max_body_chars=100)

    assert message.body == "Plain version"


def test_html_script_and_style_are_ignored() -> None:
    raw = b"""Content-Type: text/html; charset=utf-8\r
\r
<p>Visible</p><script>secret script content</script><style>secret style content</style><p>Still visible</p>"""

    message = parse_message(10, raw, max_body_chars=100)

    assert message.body == "Visible Still visible"
    assert "secret" not in message.body


def test_html_attachment_text_is_not_included() -> None:
    raw = b"""MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=x\r
\r
--x\r
Content-Type: text/html; name=secret.html\r
Content-Disposition: attachment; filename=secret.html\r
\r
<p>attachment text</p>\r
--x--\r
"""

    message = parse_message(11, raw, max_body_chars=100)

    assert message.body == ""
    assert "attachment text" not in message.body


def test_html_body_remains_bounded() -> None:
    raw = b"Content-Type: text/html; charset=utf-8\r\n\r\n<p>123456789012345</p>"

    message = parse_message(12, raw, max_body_chars=8)

    assert message.body == "12345678"



def test_message_retains_normalized_header_facts_and_repeated_authentication_results() -> None:
    raw = b"""From: Trezor <noreply@performology.com>\r
Reply-To: Support <help@reply.example>\r
Sender: relay@mailer.example\r
Return-Path: <bounce@mailer.example>\r
Message-ID: <message@performology.com>\r
List-ID: Updates <updates.example.org>\r
List-Unsubscribe: <https://example.org/unsubscribe?token=secret>\r
List-Unsubscribe-Post: List-Unsubscribe=One-Click\r
Authentication-Results: untrusted.example; spf=pass\r
Authentication-Results: mx.example; dmarc=pass\r
Received-SPF: pass\r
ARC-Authentication-Results: i=1; mx.example; arc=pass\r
DKIM-Signature: v=1; d=performology.com; s=mail\r
X-Spam-Flag: YES\r
X-Spam-Status: Yes, score=8.2\r
X-Spam-Score: 8.2\r
Subject: ***SPAM*** Update\r
\r
body"""

    message = parse_message(23, raw, max_body_chars=100)

    assert message.from_display_name == "Trezor"
    assert message.from_address == "noreply@performology.com"
    assert message.reply_to == "help@reply.example"
    assert message.sender_header == "relay@mailer.example"
    assert message.return_path == "bounce@mailer.example"
    assert message.message_id == "<message@performology.com>"
    assert message.list_id == "Updates <updates.example.org>"
    assert message.list_unsubscribe_post == ("List-Unsubscribe=One-Click",)
    assert len(message.authentication_results_raw) == 2
    assert message.received_spf_raw == ("pass",)
    assert message.arc_authentication_results_raw == ("i=1; mx.example; arc=pass",)
    assert message.dkim_signatures == ("v=1; d=performology.com; s=mail",)
    assert message.x_spam_flag == "YES"


def test_html_links_extract_only_bounded_http_hostnames() -> None:
    raw = b"""From: sender@example.org\r
Content-Type: text/html; charset=utf-8\r
\r
<a href=\"https://one.example/path?token=secret\">one</a>\r
<form action=\"http://two.example/submit\"></form>\r
<a href=\"mailto:user@example.org\">mail</a>\r
<a href=\"javascript:alert(1)\">script</a>"""

    message = parse_message(24, raw, max_body_chars=100)

    assert message.link_domains == ("one.example", "two.example")
    assert "token" not in repr(message.link_domains)


def test_malformed_and_idn_headers_are_parsed_without_losing_unicode_name() -> None:
    raw = "From: Ꮮеⅾger <support@bücher.example>\nReply-To: malformed\n\nhello".encode()

    message = parse_message(25, raw, max_body_chars=100)

    assert message.from_display_name == "Ꮮеⅾger"
    assert message.from_address == "support@bücher.example"
    assert message.reply_to == ""
    assert message.body == "hello"



def test_legacy_message_state_does_not_expose_uid() -> None:
    message = parse_message(26, b"From: sender@example.org\n\nbody", max_body_chars=100)

    assert "uid" not in message.as_state()
