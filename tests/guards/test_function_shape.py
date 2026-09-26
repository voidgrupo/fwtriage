import ast

from .source import modules

MAX_LINES = 40
MAX_DEPTH = 3
NESTING = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith, ast.Match)


def _depth(node: ast.AST, level: int = 0) -> int:
    deepest = level
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        deepest = max(deepest, _depth(child, level + _opens_level(node, child)))
    return deepest


def _opens_level(parent: ast.AST, child: ast.AST) -> bool:
    """An elif is the same level as its if, not one deeper."""
    is_elif = isinstance(parent, ast.If) and isinstance(child, ast.If) and parent.orelse == [child]
    return isinstance(child, NESTING) and not is_elif


def test_functions_are_short_and_flat() -> None:
    offenses = []
    for module in modules():
        for node in ast.walk(module.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if length > MAX_LINES:
                offenses.append(f"{module.relative}:{node.lineno} {node.name} has {length} lines")
            if _depth(node) > MAX_DEPTH:
                offenses.append(f"{module.relative}:{node.lineno} {node.name} nests {_depth(node)} levels")
    assert not offenses, f"C5: at most {MAX_LINES} lines and {MAX_DEPTH} nesting levels.\n" + "\n".join(offenses)
