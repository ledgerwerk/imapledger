from __future__ import annotations

from imapledger.config_diff import DiffDirection, render_config_diff


def test_local_to_imap_diff_has_literal_local_first_orientation() -> None:
    diff = render_config_diff(
        local_text="local\n",
        remote_text="remote\n",
        local_label="local:/tmp/config.toml",
        remote_label="imap:xyz@version",
        direction=DiffDirection.LOCAL_TO_IMAP,
    )

    assert diff.startswith("--- local:/tmp/config.toml\n+++ imap:xyz@version\n")
    assert "-local\n+remote\n" in diff


def test_imap_to_local_diff_reverses_orientation_and_equal_contents_are_empty() -> None:
    kwargs = {
        "local_text": "local\n",
        "remote_text": "remote\n",
        "local_label": "local:/tmp/config.toml",
        "remote_label": "imap:xyz@version",
    }
    diff = render_config_diff(**kwargs, direction=DiffDirection.IMAP_TO_LOCAL)

    assert diff.startswith("--- imap:xyz@version\n+++ local:/tmp/config.toml\n")
    assert "-remote\n+local\n" in diff
    assert (
        render_config_diff(
            **{**kwargs, "remote_text": "local\n"},
            direction=DiffDirection.LOCAL_TO_IMAP,
        )
        == ""
    )
