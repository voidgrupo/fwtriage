from .source import imports, modules

LAYERS = {
    "fwtriage.model": set(),
    "fwtriage.formats": {"fwtriage.model"},
    "fwtriage.engine": {"fwtriage.model", "fwtriage.formats"},
    "fwtriage.analyzers": {"fwtriage.model"},
    "fwtriage.vulns": {"fwtriage.model"},
    "fwtriage.output": {"fwtriage.model"},
}


def _layer(name: str) -> str | None:
    return next((layer for layer in LAYERS if name == layer or name.startswith(layer + ".")), None)


def test_every_import_respects_the_layer_table() -> None:
    offenses = []
    for module in modules():
        own = _layer(module.name)
        if own is None:
            continue
        for name, line in imports(module):
            target = _layer(name)
            if target is not None and target != own and target not in LAYERS[own]:
                offenses.append(f"{module.relative}:{line} {own} imports {name}")
    assert not offenses, "R8: layers only see downward (ARCHITECTURE.md §4).\n" + "\n".join(offenses)
