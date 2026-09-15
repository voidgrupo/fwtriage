import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

from fwtriage.model import Entry, EntryKind, Filesystem, disk_path, normalize

PERMISSIONS = 0o777
OWNER_WRITE = 0o600
OWNER_ACCESS = 0o700


@dataclass
class Written:
    files: int = 0
    links: int = 0
    skipped: list[str] = field(default_factory=list)


class ContainmentError(Exception):
    """A destination resolved outside the unpack target (R4)."""


def write_filesystems(target: Path, filesystems: list[tuple[str, Filesystem]]) -> Written:
    """Write each filesystem under target/<artifact path>; links last, rewritten to stay inside."""
    root = target.resolve()
    written = Written()
    for artifact, filesystem in filesystems:
        base = _inside(root, root / disk_path(artifact))
        entries = sorted(filesystem.entries.values(), key=lambda e: (e.kind is EntryKind.LINK, e.path))
        skipped = len(written.skipped)
        for entry in entries:
            try:
                _write(base, entry, written)
            except (ContainmentError, OSError):
                written.skipped.append(entry.path)
        written.skipped[skipped:] = [f"{artifact} › {path}" for path in written.skipped[skipped:]]
        _restore_directory_modes(base, filesystem)
    return written


def _restore_directory_modes(base: Path, filesystem: Filesystem) -> None:
    """Applied last and deepest first, so a restrictive directory never blocks its own children."""
    directories = [e for e in filesystem.entries.values() if e.kind is EntryKind.DIRECTORY and e.path != "/"]
    for entry in sorted(directories, key=lambda e: -e.path.count("/")):
        destination = base / entry.path.lstrip("/")
        if destination.is_dir() and not destination.is_symlink():
            destination.chmod(_safe_mode(entry.mode) | OWNER_ACCESS)


def _write(base: Path, entry: Entry, written: Written) -> None:
    destination = _inside(base, base / entry.path.lstrip("/")) if entry.path != "/" else base
    if entry.kind is EntryKind.DIRECTORY:
        destination.mkdir(parents=True, exist_ok=True)
    elif entry.kind is EntryKind.FILE:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(entry.data)
        destination.chmod(_safe_mode(entry.mode) | OWNER_WRITE)
        written.files += 1
    elif entry.kind is EntryKind.LINK:
        _link(base, entry, destination, written)
    else:
        written.skipped.append(entry.path)


def _safe_mode(mode: int) -> int:
    """The image's permission bits without setuid, setgid and sticky; 0o644 when it has none."""
    return mode & PERMISSIONS or 0o644


def _link(base: Path, entry: Entry, destination: Path, written: Written) -> None:
    virtual = normalize(posixpath.join(posixpath.dirname(entry.path), entry.target))
    relative = os.path.relpath(base / virtual.lstrip("/"), destination.parent)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        written.skipped.append(entry.path)
        return
    try:
        destination.symlink_to(relative)
        written.links += 1
    except OSError:
        written.skipped.append(entry.path)


def _inside(root: Path, candidate: Path) -> Path:
    """Refuse any destination outside root. Links are rewritten to point inside root, so
    following one of them while writing can never leave it either."""
    resolved = Path(os.path.normpath(candidate))
    if resolved != root and root not in resolved.parents:
        raise ContainmentError(f"{candidate} is outside {root}")
    return resolved
