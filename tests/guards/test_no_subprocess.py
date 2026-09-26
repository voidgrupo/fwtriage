from .source import calls, imports, modules

FORBIDDEN_MODULES = ("subprocess", "pty", "multiprocessing")
FORBIDDEN_CALLS = ("os.system", "os.popen", "os.exec", "os.spawn", "os.fork", "os.posix_spawn")


def test_no_module_starts_a_process() -> None:
    offenses = []
    for module in modules():
        offenses += [
            f"{module.relative}:{line} imports {name}"
            for name, line in imports(module)
            if name.split(".")[0] in FORBIDDEN_MODULES
        ]
        offenses += [
            f"{module.relative}:{line} calls {name}" for name, line in calls(module) if name.startswith(FORBIDDEN_CALLS)
        ]
    assert not offenses, "R1: fwtriage never starts another program; parse it instead.\n" + "\n".join(offenses)
