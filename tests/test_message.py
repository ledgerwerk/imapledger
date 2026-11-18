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
