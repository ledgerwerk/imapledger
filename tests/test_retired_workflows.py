from __future__ import annotations

from importlib import import_module

from imapledger.application.operation_registry import OPERATION_SPECS


def test_retired_category_modules_have_no_runtime_exports() -> None:
    modules = (
        "imapledger.action_service",
        "imapledger.analysis_service",
        "imapledger.application.browsing",
        "imapledger.application.legacy_clean",
        "imapledger.application.state",
        "imapledger.classification_state",
        "imapledger.classifier",
        "imapledger.cleaner",
        "imapledger.policy",
        "imapledger.rule_service",
        "imapledger.rule_test_service",
        "imapledger.settings_service",
        "imapledger.tui.legacy_clean",
    )

    for module_name in modules:
        module = import_module(module_name)
        assert not [name for name in vars(module) if not name.startswith("_")], module_name


def test_operation_registry_has_no_category_classification_commands() -> None:
    paths = {spec.cli_path for spec in OPERATION_SPECS}

    assert (
        not {
            ("state", "status"),
            ("state", "reset"),
            ("review", "list"),
            ("mail", "classify"),
        }
        & paths
    )
