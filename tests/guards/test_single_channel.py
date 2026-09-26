import ast

from .source import modules

ALLOWED = ("fwtriage/output/", "fwtriage/cli.py")


def test_no_print_outside_output_and_cli() -> None:
    offenses = []
    for module in modules():
        if module.relative.startswith(ALLOWED):
            continue
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                offenses.append(f"{module.relative}:{node.lineno} calls print")
            if (
                isinstance(node, ast.Attribute)
                and node.attr in ("stdout", "stderr")
                and getattr(node.value, "id", "") == "sys"
            ):
                offenses.append(f"{module.relative}:{node.lineno} touches sys.{node.attr}")
    assert not offenses, "C4: user-facing output goes through fwtriage.output or the CLI.\n" + "\n".join(offenses)
