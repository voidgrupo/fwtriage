import tomllib

from .source import ROOT

ALLOWED = {"pyelftools", "pysquashfsimage"}


def test_runtime_dependencies_are_the_allowed_pure_python_list() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    names = {
        dependency.split(">")[0].split("=")[0].split("<")[0].strip().lower() for dependency in project["dependencies"]
    }
    assert names == ALLOWED, f"R7: runtime dependencies must stay pure Python; record a new one in D2. Found {names}"
