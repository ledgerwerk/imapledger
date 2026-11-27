from __future__ import annotations

import ast
from pathlib import Path

from imapledger.application.operation_registry import OPERATION_SPECS, OperationContext

ROOT = Path(__file__).resolve().parents[1]


def _command_name(call: ast.Call, function_name: str) -> str:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return function_name


def _cli_group_prefixes(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    prefixes = {"app": ()}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "add_typer":
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "app" or not node.args:
            continue
        group = node.args[0]
        name = next(
            (
                keyword.value.value
                for keyword in node.keywords
                if keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ),
            None,
        )
        if isinstance(group, ast.Name) and name is not None:
            prefixes[group.id] = (name,)
    return prefixes


def _decorated_cli_paths(tree: ast.Module) -> set[tuple[str, ...]]:
    prefixes = _cli_group_prefixes(tree)
    paths: set[tuple[str, ...]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            if decorator.func.attr != "command" or not isinstance(decorator.func.value, ast.Name):
                continue
            prefix = prefixes.get(decorator.func.value.id)
            if prefix is not None:
                paths.add(prefix + (_command_name(decorator, node.name),))
    return paths


def _config_store_paths(tree: ast.Module) -> set[tuple[str, ...]]:
    paths: set[tuple[str, ...]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Call):
            continue
        command_call = node.func
        if not isinstance(command_call.func, ast.Attribute) or command_call.func.attr != "command":
            continue
        if not isinstance(command_call.func.value, ast.Name) or command_call.func.value.id != "app":
            continue
        if not command_call.args or not isinstance(command_call.args[0], ast.Constant):
            continue
        command = command_call.args[0].value
        if isinstance(command, str):
            paths.add(("config", command))
    return paths


def test_every_cli_command_except_ui_has_a_tui_partner() -> None:
    cli_tree = ast.parse((ROOT / "imapledger/cli.py").read_text(encoding="utf-8"))
    store_tree = ast.parse((ROOT / "imapledger/config_store_cli.py").read_text(encoding="utf-8"))
    cli_paths = _decorated_cli_paths(cli_tree) | _config_store_paths(store_tree)
    cli_paths.discard(("clean",))
    cli_paths.discard(("mail", "classify"))
    registry_paths = {spec.cli_path for spec in OPERATION_SPECS}

    assert cli_paths <= registry_paths
    exceptions = [spec for spec in OPERATION_SPECS if spec.tui_partner is None]
    assert [spec.cli_path for spec in exceptions] == [("ui",)]
    assert all(spec.tui_partner for spec in OPERATION_SPECS if spec.cli_path != ("ui",))


def test_unavailable_operations_include_a_context_reason() -> None:
    empty_context = OperationContext()
    unavailable = [spec for spec in OPERATION_SPECS if spec.tui_partner is not None and spec.required_context]

    assert unavailable
    assert all(spec.unavailable_reason(empty_context) for spec in unavailable)
