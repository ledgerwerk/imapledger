from pathlib import Path

from imapledger.config import ImapSettings, Settings, SpamSettings, load_settings, write_settings


def test_config_roundtrip_does_not_store_password(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(folder="Spam", threshold=0.97),
    )
    write_settings(settings, path)

    text = path.read_text(encoding="utf-8")
    assert "password" not in text.lower()
    assert load_settings(path) == settings
