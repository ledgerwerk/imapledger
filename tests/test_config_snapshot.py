from __future__ import annotations

from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

import pytest

from imapledger.config_errors import ConfigSnapshotError, ConfigSnapshotIntegrityError
from imapledger.config_snapshot import (
    ConfigSnapshot,
    build_version_id,
    create_snapshot,
    expand_default_path,
    normalize_tool_name,
    parse_snapshot_message,
    parse_snapshot_metadata,
    portable_default_path,
    sensitive_fields,
    serialize_snapshot,
    sha256_bytes,
)

CREATED = datetime(2026, 11, 21, 16, 42, 33, 991472, tzinfo=timezone.utc)


def _snapshot(content: bytes = "alpha = '✓'\r\n".encode()) -> ConfigSnapshot:
    return create_snapshot(
        tool="XYZ",
        content=content,
        default_path="~/.config/xyz/config.toml",
        created_at=CREATED,
    )


def test_tool_identifiers_normalize_and_reject_paths_or_whitespace() -> None:
    assert normalize_tool_name("PyJev") == "pyjev"
    for tool in ("", " ", "../xyz", "a..b", "a/b", "a\\b", "x\ny", "x" * 65):
        with pytest.raises(ConfigSnapshotError):
            normalize_tool_name(tool)


def test_home_paths_are_portable_and_outside_paths_remain_absolute(tmp_path: Path) -> None:
    home = tmp_path / "home"
    inside = home / ".config" / "xyz" / "config.toml"
    outside = tmp_path / "etc" / "xyz.toml"

    assert portable_default_path(inside, home=home) == "~/.config/xyz/config.toml"
    assert portable_default_path(outside, home=home) == str(outside.resolve())
    assert expand_default_path("~/.config/xyz/config.toml", home=home) == inside


def test_utf8_crlf_payload_roundtrips_exactly_and_hashes_bytes() -> None:
    content = "name = 'café'\r\nemoji = '✓'\n".encode()
    snapshot = _snapshot(content)
    parsed = parse_snapshot_message(serialize_snapshot(snapshot, username="user@example.org"))

    assert parsed.content == content
    assert parsed.meta.content_sha256 == sha256_bytes(content)
    assert parsed.meta.size_bytes == len(content)
    assert parsed.meta.tool == "xyz"


def test_lf_payload_roundtrips_exactly() -> None:
    content = b"one = 1\ntwo = 2\n"
    parsed = parse_snapshot_message(serialize_snapshot(_snapshot(content), username="user@example.org"))

    assert parsed.content == content


def test_version_id_is_stable_human_readable_and_metadata_sensitive() -> None:
    snapshot = _snapshot()
    expected = build_version_id(
        tool=snapshot.meta.tool,
        created_at=CREATED,
        default_path=snapshot.meta.default_path,
        content_sha256=snapshot.meta.content_sha256,
    )

    assert snapshot.meta.version_id == expected
    assert snapshot.meta.version_id.startswith("20261121T164233.991472Z-")
    assert len(snapshot.meta.version_id.rsplit("-", 1)[1]) == 12
    assert (
        snapshot.meta.version_id
        != create_snapshot(
            tool="xyz",
            content=snapshot.content,
            default_path="~/.config/other/config.toml",
            created_at=CREATED,
        ).meta.version_id
    )


def test_metadata_fetch_does_not_need_to_decode_the_attachment() -> None:
    snapshot = _snapshot()
    raw = serialize_snapshot(snapshot, username="user@example.org")

    meta = parse_snapshot_metadata(raw, uid=17, uidvalidity=33)

    assert meta.version_id == snapshot.meta.version_id
    assert meta.uid == 17
    assert meta.uidvalidity == 33


def test_mime_contains_readable_mirror_and_authoritative_attachment() -> None:
    snapshot = _snapshot()
    message = BytesParser(policy=default).parsebytes(serialize_snapshot(snapshot, username="user@example.org"))
    parts = list(message.walk())

    assert message.is_multipart()
    assert any(part.get_content_type() == "text/plain" for part in parts)
    assert [part for part in parts if part.get_content_disposition() == "attachment"]


def test_missing_authoritative_attachment_is_rejected() -> None:
    message = BytesParser(policy=default).parsebytes(serialize_snapshot(_snapshot(), username="user@example.org"))
    message.clear_content()
    message.set_content("readable mirror only")

    with pytest.raises(ConfigSnapshotIntegrityError, match="exactly one authoritative attachment"):
        parse_snapshot_message(message.as_bytes())


def test_multiple_authoritative_attachments_are_rejected() -> None:
    message = BytesParser(policy=default).parsebytes(serialize_snapshot(_snapshot(), username="user@example.org"))
    message.add_attachment(b"second", maintype="application", subtype="octet-stream", filename="second.toml")

    with pytest.raises(ConfigSnapshotIntegrityError, match="exactly one authoritative attachment"):
        parse_snapshot_message(message.as_bytes())


def test_hash_mismatch_is_rejected() -> None:
    message = BytesParser(policy=default).parsebytes(serialize_snapshot(_snapshot(), username="user@example.org"))
    message.clear_content()
    message.set_content("mirror")
    message.add_attachment(
        b"z" * len(_snapshot().content),
        maintype="application",
        subtype="octet-stream",
        filename="config.toml",
    )

    with pytest.raises(ConfigSnapshotIntegrityError, match="SHA-256"):
        parse_snapshot_message(message.as_bytes())


def test_size_mismatch_and_configured_limit_are_rejected() -> None:
    message = BytesParser(policy=default).parsebytes(serialize_snapshot(_snapshot(), username="user@example.org"))
    message.replace_header("X-Imapledger-Size", str(len(_snapshot().content) + 1))
    with pytest.raises(ConfigSnapshotIntegrityError, match="size"):
        parse_snapshot_message(message.as_bytes())

    with pytest.raises(ConfigSnapshotError, match="limit"):
        create_snapshot(
            tool="xyz",
            content=b"long",
            default_path="~/config.toml",
            max_file_bytes=3,
        )


def test_unsupported_schema_and_malformed_headers_fail() -> None:
    message = BytesParser(policy=default).parsebytes(serialize_snapshot(_snapshot(), username="user@example.org"))
    message.replace_header("X-Imapledger-Schema", "2")
    with pytest.raises(ConfigSnapshotIntegrityError, match="unsupported"):
        parse_snapshot_metadata(message)

    malformed = BytesParser(policy=default).parsebytes(serialize_snapshot(_snapshot(), username="user@example.org"))
    del malformed["X-Imapledger-Filename"]
    with pytest.raises(ConfigSnapshotIntegrityError, match="exactly one X-Imapledger-Filename"):
        parse_snapshot_metadata(malformed)


def test_invalid_utf8_nul_and_header_injection_are_rejected() -> None:
    for content in (b"\xff", b"a\x00b"):
        with pytest.raises(ConfigSnapshotError):
            create_snapshot(tool="xyz", content=content, default_path="~/config.toml")
    with pytest.raises(ConfigSnapshotError):
        create_snapshot(tool="xyz", content=b"ok", default_path="~/config.toml\r\nX-Evil: yes")
    with pytest.raises(ConfigSnapshotError):
        create_snapshot(tool="xyz", content=b"ok", default_path="~/config.toml", filename="../evil")


def test_serialization_rejects_header_injection_in_username() -> None:
    with pytest.raises(ConfigSnapshotError, match="header value"):
        serialize_snapshot(_snapshot(), username="user@example.org\r\nX-Evil: yes")


def test_secret_scan_hides_values_and_allows_environment_placeholders() -> None:
    findings = sensitive_fields(
        'password = "plain-value"\n'
        "api_key = ${TOKEN}\n"
        "access_token=$TOKEN\n"
        "refresh_token=env:REFRESH_TOKEN\n"
        "Authorization: Bearer actual-token\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
    )

    assert [(item.line_number, item.field) for item in findings] == [
        (1, "password"),
        (5, "authorization bearer token"),
        (6, "private key"),
    ]
    assert all("plain-value" not in item.field for item in findings)
