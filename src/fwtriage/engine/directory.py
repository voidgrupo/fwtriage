import os
from dataclasses import replace
from pathlib import Path

from fwtriage.model import Budget, Entry, EntryKind, Filesystem, Notice, normalize


def read_directory(root: Path, budget: Budget) -> tuple[Filesystem, list[Notice]]:
    """Read an extracted root filesystem without following any link (F1); what cannot be read
    becomes a notice, never an abort."""
    filesystem = Filesystem("directory")
    notices: list[Notice] = []

    def unreadable(error: OSError) -> None:
        notices.append(Notice("unreadable", error.strerror or str(error), _virtual(root, Path(str(error.filename)))))

    for current, directories, files in os.walk(root, followlinks=False, onerror=unreadable):
        base = Path(current)
        for name in sorted(directories) + sorted(files):
            budget.count_entry()
            try:
                filesystem.add(_entry(root, base / name, budget))
            except OSError as error:
                unreadable(error)
    return filesystem, notices


def _virtual(root: Path, path: Path) -> str:
    try:
        return normalize(path.relative_to(root).as_posix())
    except ValueError:
        return str(path)


def _entry(root: Path, path: Path, budget: Budget) -> Entry:
    status = path.lstat()
    entry = Entry(_virtual(root, path), EntryKind.OTHER, status.st_mode, status.st_uid, status.st_gid)
    if path.is_symlink():
        return replace(entry, kind=EntryKind.LINK, target=str(path.readlink()))
    if path.is_dir():
        return replace(entry, kind=EntryKind.DIRECTORY)
    if path.is_file():
        budget.charge(status.st_size)
        return replace(entry, kind=EntryKind.FILE, data=path.read_bytes())
    return entry
