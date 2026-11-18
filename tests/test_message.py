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
