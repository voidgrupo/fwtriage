import tomllib
from pathlib import Path
from typing import Any

from fwtriage.model import Confidence, Ignore, Limits, Policy, PolicyError, Severity

FILE_NAME = "fwtriage.toml"
LIMIT_KEYS = {"total-bytes": "total_bytes", "entry-bytes": "entry_bytes", "depth": "depth", "entries": "entries"}
KNOWN_KEYS = {"fail-on", "min-confidence", "limits", "ignore"}


def discover(start: Path) -> Path | None:
    for directory in (start, *start.parents):
        for candidate in (directory / FILE_NAME, directory / "pyproject.toml"):
            if candidate.is_file() and _section(candidate) is not None:
                return candidate
    return None


def load(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    section = _section(path)
    if section is None:
        raise PolicyError(f"{path}: no fwtriage settings found")
    return parse(section, str(path))


def _section(path: Path) -> dict[str, Any] | None:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise PolicyError(f"{path}: {error}") from error
    if path.name == "pyproject.toml":
        section = document.get("tool", {}).get("fwtriage")
        return section if isinstance(section, dict) else None
    return document


def parse(section: dict[str, Any], origin: str) -> Policy:
    unknown = set(section) - KNOWN_KEYS
    if unknown:
        raise PolicyError(f"{origin}: unknown keys {', '.join(sorted(unknown))}")
    try:
        fail_on = Severity.parse(str(section.get("fail-on", "high")))
        confidence = Confidence.parse(str(section.get("min-confidence", "likely")))
    except ValueError as error:
        raise PolicyError(f"{origin}: {error}") from error
    return Policy(
        fail_on, confidence, _ignores(section.get("ignore", []), origin), _limits(section.get("limits", {}), origin)
    )


def _ignores(raw: Any, origin: str) -> tuple[Ignore, ...]:
    if not isinstance(raw, list):
        raise PolicyError(f"{origin}: 'ignore' must be an array of tables")
    ignores = []
    for item in raw:
        if not isinstance(item, dict) or not item.get("rule") or not str(item.get("reason", "")).strip():
            raise PolicyError(f"{origin}: every ignore needs 'rule' and a non-empty 'reason'")
        ignores.append(Ignore(str(item["rule"]), str(item["reason"]).strip(), item.get("path")))
    return tuple(ignores)


def _limits(raw: Any, origin: str) -> Limits:
    if not isinstance(raw, dict) or set(raw) - set(LIMIT_KEYS):
        raise PolicyError(f"{origin}: 'limits' accepts {', '.join(LIMIT_KEYS)}")
    values = {LIMIT_KEYS[key]: value for key, value in raw.items()}
    if any(not isinstance(value, int) or value <= 0 for value in values.values()):
        raise PolicyError(f"{origin}: limits must be positive integers")
    return Limits(**values)
