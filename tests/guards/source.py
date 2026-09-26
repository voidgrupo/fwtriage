import ast
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "fwtriage"


@dataclass(frozen=True)
class Module:
    path: Path
    name: str
    tree: ast.Module

    @property
    def relative(self) -> str:
        return self.path.relative_to(ROOT / "src").as_posix()


def modules() -> Iterator[Module]:
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(ROOT / "src").with_suffix("")
        name = ".".join(part for part in relative.parts if part != "__init__")
        yield Module(path, name, ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))


def imports(module: Module) -> Iterator[tuple[str, int]]:
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            yield from ((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            yield from _from_import(module, node)


def _from_import(module: Module, node: ast.ImportFrom) -> Iterator[tuple[str, int]]:
    if node.level == 0:
        base = node.module or ""
    else:
        package = module.name.split(".") if module.path.name == "__init__.py" else module.name.split(".")[:-1]
        anchor = package[: len(package) - node.level + 1]
        base = ".".join([*anchor, node.module] if node.module else anchor)
    yield base, node.lineno
    for alias in node.names:
        yield f"{base}.{alias.name}", node.lineno


def calls(module: Module) -> Iterator[tuple[str, int]]:
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Call):
            yield dotted(node.func), node.lineno


def dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""
