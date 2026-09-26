import ast

from .source import Module, modules

ALLOWED = ("fwtriage/output/", "fwtriage/vulns/cache.py")
WRITING_METHODS = {
    "write_text",
    "write_bytes",
    "mkdir",
    "symlink_to",
    "hardlink_to",
    "touch",
    "chmod",
    "unlink",
    "rename",
}
WRITE_MODES = ("w", "a", "x", "+")


def _offenses(module: Module) -> list[str]:
    found = []
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in WRITING_METHODS:
            found.append(f"{module.relative}:{node.lineno} calls .{node.func.attr}()")
        if _opens_for_writing(node):
            found.append(f"{module.relative}:{node.lineno} opens a file for writing")
    return found


def _opens_for_writing(node: ast.Call) -> bool:
    name = (
        node.func.id
        if isinstance(node.func, ast.Name)
        else node.func.attr
        if isinstance(node.func, ast.Attribute)
        else ""
    )
    if name != "open":
        return False
    modes = list(node.args[1:2]) + [kw.value for kw in node.keywords if kw.arg == "mode"]
    return any(
        isinstance(m, ast.Constant) and isinstance(m.value, str) and any(c in m.value for c in WRITE_MODES)
        for m in modes
    )


def test_only_output_and_cache_write_files() -> None:
    offenses = [o for module in modules() if not module.relative.startswith(ALLOWED) for o in _offenses(module)]
    assert not offenses, "R4: only fwtriage.output and the NVD cache write files.\n" + "\n".join(offenses)
