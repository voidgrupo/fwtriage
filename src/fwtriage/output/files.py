from pathlib import Path


def write_text(path: Path, content: str) -> None:
    """The one place a report file is written (R4)."""
    path.write_text(content, encoding="utf-8")
