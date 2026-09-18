import hashlib
import json
import os
from pathlib import Path
from typing import Any

MAX_AGE_DAYS = 7
SECONDS_PER_DAY = 86_400


def default_directory() -> Path:
    if override := os.environ.get("FWTRIAGE_CACHE"):
        return Path(override)
    base = os.environ.get("XDG_CACHE_HOME") or os.environ.get("LOCALAPPDATA") or str(Path.home() / ".cache")
    return Path(base) / "fwtriage" / "nvd"


class Cache:
    """NVD responses on disk, keyed by query, with the date they were fetched (D8)."""

    def __init__(self, directory: Path | None = None, max_age_days: int = MAX_AGE_DAYS) -> None:
        self.directory = directory or default_directory()
        self.max_age = max_age_days * SECONDS_PER_DAY

    def get(self, key: str, now: float) -> tuple[dict[str, Any], str] | None:
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if now - float(stored.get("fetched_at", 0)) > self.max_age:
            return None
        return stored["payload"], str(stored["fetched_on"])

    def put(self, key: str, payload: dict[str, Any], now: float, today: str) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        record = {"key": key, "fetched_at": now, "fetched_on": today, "payload": payload}
        self._path(key).write_text(json.dumps(record, sort_keys=True), encoding="utf-8")

    def _path(self, key: str) -> Path:
        return self.directory / f"{hashlib.sha256(key.encode()).hexdigest()[:32]}.json"
