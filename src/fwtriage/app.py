import hashlib
import mmap
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fwtriage.analyzers import ANALYZERS, Analysis, Analyzer, Context
from fwtriage.engine import Result, Unpacker, read_directory
from fwtriage.formats import REGISTRY
from fwtriage.model import Budget, Finding, Image, Notice, Policy, Report, Suppressed


def scan(path: Path | str, policy: Policy | None = None, online: bool = False) -> Report:
    """Run the whole pipeline on an image file or an extracted directory (F22)."""
    target = Path(path)
    policy = policy or Policy()
    budget = Budget(policy.limits)
    result, image = _unpack_directory(target, budget) if target.is_dir() else _unpack_file(target, budget)
    analysis = _analyze(result)
    report = Report(image, result.artifacts, notices=list(result.notices))
    report.components, report.binaries = analysis.components, analysis.binaries
    _apply_policy(report, result.findings + analysis.findings, policy)
    if online:
        _match_vulnerabilities(report, policy)
    else:
        report.notices.append(Notice("offline", "vulnerability matching skipped; pass --online to enable it", "scan"))
    report.failed = any(policy.fails(finding) for finding in report.findings)
    report.sort()
    return report


def extract(path: Path | str, policy: Policy | None = None) -> Result:
    """Unpack without analysis, for the `unpack` command."""
    target = Path(path)
    budget = Budget((policy or Policy()).limits)
    result, _ = _unpack_directory(target, budget) if target.is_dir() else _unpack_file(target, budget)
    return result


def _unpack_file(target: Path, budget: Budget) -> tuple[Result, Image]:
    with _mapped(target) as buffer:
        image = Image(target.name, len(buffer), hashlib.sha256(buffer).hexdigest())
        return Unpacker(REGISTRY, budget).run(buffer, target.name), image


def _unpack_directory(target: Path, budget: Budget) -> tuple[Result, Image]:
    unpacker = Unpacker(REGISTRY, budget)
    filesystem, notices = read_directory(target, budget)
    unpacker.result.notices.extend(notices)
    unpacker.add_filesystem(target.name, filesystem)
    return unpacker.result, Image(target.name, 0, "")


@contextmanager
def _mapped(target: Path) -> Iterator[bytes | mmap.mmap]:
    with target.open("rb") as handle:
        if target.stat().st_size == 0:
            yield b""
            return
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buffer:
            yield buffer


def _analyze(result: Result) -> Analysis:
    total = Analysis()
    for located in result.filesystems:
        context = Context(located.filesystem, located.path)
        for analyzer in ANALYZERS:
            total.merge(_run_analyzer(analyzer, context, result))
    return total


def _run_analyzer(analyzer: Analyzer, context: Context, result: Result) -> Analysis:
    try:
        return analyzer.analyze(context)
    except Exception as error:  # noqa: BLE001
        # One analyzer failing on a hostile filesystem must not take the whole report down;
        # the failure is reported, and the pipeline-robustness guard fails on it in tests.
        message = f"{analyzer.area}: {type(error).__name__}: {error}"[:300]
        result.notices.append(Notice("analyzer-failed", message, context.artifact))
        return Analysis()


def _apply_policy(report: Report, findings: list[Finding], policy: Policy) -> None:
    for finding in findings:
        ignore = policy.ignored_by(finding)
        if ignore is None:
            report.findings.append(finding)
        else:
            report.suppressed.append(Suppressed(finding, ignore))


def _match_vulnerabilities(report: Report, policy: Policy) -> None:
    from fwtriage.vulns import match  # noqa: PLC0415

    findings = match(report.components)
    _apply_policy(report, findings, policy)
