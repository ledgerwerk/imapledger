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


def test_message_exposes_body_source_truncation_and_attachment_metadata() -> None:
    raw = b"""MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=x\r
\r
--x\r
Content-Type: text/plain\r
\r
1234567890\r
--x\r
Content-Type: application/pdf; name=one.pdf\r
Content-Disposition: attachment; filename=one.pdf\r
\r
ignored\r
--x--\r
"""

    message = parse_message(27, raw, max_body_chars=5, size_bytes=len(raw))

    assert message.body == "12345"
    assert message.body_truncated
    assert message.body_source == "plain"
    assert message.has_attachments
    assert message.attachment_count == 1
    assert message.size_bytes == len(raw)


def test_empty_message_body_source_is_none() -> None:
    message = parse_message(28, b"Subject: no body\r\n\r\n", max_body_chars=20)

    assert message.body_source == "none"
    assert not message.body_truncated
    assert not message.has_attachments


def test_embedded_inline_cid_image_is_counted_without_attachment_filename():
    raw = b"""MIME-Version: 1.0\r
Content-Type: multipart/related; boundary=x\r
\r
--x\r
Content-Type: text/html; charset=utf-8\r
\r
<p>Invoice</p><img src=\"cid:bill-image\" alt=\"bill\">\r
--x\r
Content-Type: image/png\r
Content-ID: <bill-image>\r
Content-Disposition: inline\r
Content-Transfer-Encoding: base64\r
\r
AQID\r
--x--\r
"""
    message = parse_message(29, raw, max_body_chars=100)

    assert message.image_count == 1
    image = message.images[0]
    assert image.content_type == "image/png"
    assert image.content_id == "bill-image"
    assert image.disposition == "inline"
    assert image.data == b"\x01\x02\x03"
    assert image.classifiable
    assert message.remote_image_count == 0
    assert message.attachment_count == 0


def test_attached_jpeg_and_unsupported_and_empty_images_preserve_attachment_count():
    raw = b"""MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=x\r
\r
--x\r
Content-Type: image/jpeg; name=receipt.jpg\r
Content-Disposition: attachment; filename=receipt.jpg\r
Content-Transfer-Encoding: base64\r
\r
/9j/2Q==\r
--x\r
Content-Type: image/gif\r
Content-Transfer-Encoding: base64\r
\r\nR0lGODlh\r
--x\r
Content-Type: image/png\r
Content-Transfer-Encoding: base64\r
\r\n\r
--x--\r
"""
    message = parse_message(30, raw, max_body_chars=100)

    assert message.image_count == 3
    assert message.attachment_count == 1
    assert message.images[0].filename == "receipt.jpg"
    assert message.images[0].classifiable
    assert not message.images[1].classifiable
    assert message.images[1].skip_reason == "image/gif is not supported by the visual analyzer"
    assert not message.images[2].classifiable
    assert message.images[2].skip_reason == "image payload is empty or malformed"


def test_html_remote_image_references_are_bounded_deduplicated_and_private_in_repr():
    urls = [f"https://img{index}.example/picture?token=secret{index}" for index in range(55)]
    html = "<p>Newsletter</p>" + "".join(f'<img src="{url}" alt="{"a" * 600}">' for url in [urls[0], *urls])
    raw = f"Content-Type: text/html; charset=utf-8\r\n\r\n{html}".encode()
    message = parse_message(31, raw, max_body_chars=100)

    assert message.body == "Newsletter"
    assert message.remote_image_count == 50
    assert message.remote_images[0].index == 1
    assert message.remote_images[0].host == "img0.example"
    assert len(message.remote_images[0].alt) == 500
    assert "token=secret" not in repr(message)
    assert "token=secret" not in repr(message.as_state())
    assert "token=secret" not in message.body
    assert "data:image" not in repr(message)
