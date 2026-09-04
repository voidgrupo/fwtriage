from fwtriage.analyzers import Analysis, Context
from fwtriage.analyzers.base import Analyzer
from fwtriage.model import Entry, EntryKind, Filesystem


def filesystem(files: dict[str, bytes], links: dict[str, str] | None = None) -> Filesystem:
    fs = Filesystem("test")
    for path, data in files.items():
        fs.add(Entry(path, EntryKind.FILE, 0o755, data=data))
    for path, target in (links or {}).items():
        fs.add(Entry(path, EntryKind.LINK, target=target))
    return fs


def run(analyzer: Analyzer, fs: Filesystem) -> Analysis:
    return analyzer.analyze(Context(fs, "rootfs"))


def rules(analysis: Analysis) -> list[str]:
    return sorted(finding.rule for finding in analysis.findings)
