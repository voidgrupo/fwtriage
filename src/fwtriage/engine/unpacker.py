from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field

from fwtriage.formats.base import Format, Stream, Unpacked
from fwtriage.model import (
    Artifact,
    Budget,
    BudgetExceeded,
    Confidence,
    Evidence,
    Filesystem,
    Finding,
    FormatError,
    FormatKind,
    Location,
    MissingExtra,
    Notice,
    Region,
    Severity,
    Signing,
)
from fwtriage.model.entropy import is_high, is_uniform

from . import signing
from .scanner import PROBE_LIMIT, Buffer, Candidates

ENTROPY_SPAN = 64 * 1024
ENTROPY_THRESHOLD = 7.9
NESTED_MINIMUM = 64 * 1024
SEPARATOR = " › "


IDENTIFIED_LIMIT = 256
UNATTRIBUTED_BYTES = 64 * 1024
UNATTRIBUTED_SHARE = 0.05
PADDING_BLOCK = 4096
LEADING_HEADER = 16
LISTED_SPANS = 3


@dataclass
class _Walk:
    candidates: Candidates
    artifacts: list[Artifact] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    covered: int = 0
    identified: int = 0


@dataclass
class Located:
    path: str
    filesystem: Filesystem


@dataclass
class Result:
    artifacts: list[Artifact] = field(default_factory=list)
    filesystems: list[Located] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class Unpacker:
    """Builds the artifact tree of a buffer, recursively, under one budget (F2, F4, F5)."""

    def __init__(self, formats: Sequence[Format], budget: Budget) -> None:
        self.formats = {fmt.name: fmt for fmt in formats}
        self.budget = budget
        self.result = Result()
        self.undecodable: set[str] = set()
        self.failed: set[str] = set()

    def run(self, buffer: Buffer, name: str) -> Result:
        self.result.artifacts = self._scan(buffer, "", 0, top=name)
        incomplete = self._unattributed(buffer, name)
        doubt = self._signing_doubt(buffer, incomplete)
        if doubt and signing.would_flag_unsigned(self.result.artifacts):
            self._notice("signing-undetermined", f"not judged as unsigned: {doubt}", name)
        self.result.findings.extend(signing.judge(self.result.artifacts, name, unsure=doubt is not None))
        return self.result

    def _unattributed(self, buffer: Buffer, name: str) -> bool:
        unknown, largest = unattributed(memoryview(buffer), self.result.artifacts, self.failed)
        size = len(buffer)
        if size and unknown >= UNATTRIBUTED_BYTES and unknown / size >= UNATTRIBUTED_SHARE:
            start, end = largest
            share = f"{unknown / size:.0%} of the image ({unknown:,} bytes) is in no region and is not padding"
            message = f"{share}; largest span 0x{start:x}–0x{end:x}"
            self._notice("unattributed", message, name)
            return True
        return False

    def _signing_doubt(self, buffer: Buffer, incomplete: bool) -> str | None:
        """Why the absence of a signature cannot be asserted: the signature may sit in what fwtriage
        did not understand — a vendor header, an unrecognized part, or a container that failed."""
        first = min((a.offset for a in self.result.artifacts), default=None)
        if first is not None and _non_padding(memoryview(buffer), 0, first)[0] >= LEADING_HEADER:
            return f"{first:,} bytes of unrecognized header precede the first region"
        if incomplete:
            return "a meaningful part of the image is in no recognized region"
        if self.failed:
            return f"{len(self.failed)} container or filesystem could not be unpacked"
        return None

    def add_filesystem(self, path: str, filesystem: Filesystem) -> None:
        self.result.filesystems.append(Located(path, filesystem))
        self.result.artifacts.extend(self._search_filesystem(filesystem, path, 1))

    def _scan(
        self, buffer: Buffer, prefix: str, depth: int, top: str | None = None, entropy: bool = True
    ) -> list[Artifact]:
        """Probe in offset order, skipping whatever an earlier region already covers (F2)."""
        label = prefix or top or "image"
        walk = _Walk(Candidates(buffer, self.formats.values()))
        for offset, fmt in walk.candidates:
            if offset < walk.covered:
                continue
            region = walk.candidates.probe(fmt, offset)
            if region is not None:
                self._accept(buffer, region, prefix, depth, walk)
        self._walk_notices(walk, label)
        if entropy:
            self._flag_unidentified(buffer, walk.artifacts, walk.regions, label)
        return walk.artifacts

    def _accept(self, buffer: Buffer, region: Region, prefix: str, depth: int, walk: "_Walk") -> None:
        walk.regions.append(region)
        if region.kind is FormatKind.IDENTIFIED:
            walk.identified += 1
            if walk.identified <= IDENTIFIED_LIMIT:
                walk.artifacts.append(self._visit(buffer, region, prefix, depth))
            return
        artifact = self._visit(buffer, region, prefix, depth)
        if artifact.size is None:
            walk.candidates.drop(region.format)
            if region.kind is FormatKind.COMPRESSION and artifact.path in self.undecodable:
                return
        walk.artifacts.append(artifact)
        walk.covered = max(walk.covered, region.offset + (artifact.size or 0))

    def _walk_notices(self, walk: "_Walk", label: str) -> None:
        for name, offset in walk.candidates.limited:
            self._notice("probe-limit", f"{name}: stopped after {PROBE_LIMIT:,} candidates, at 0x{offset:x}", label)
        if walk.identified > IDENTIFIED_LIMIT:
            hidden = walk.identified - IDENTIFIED_LIMIT
            self._notice("identified-limit", f"{hidden:,} more ELF/PEM regions not listed", label)

    def _visit(self, buffer: Buffer, region: Region, prefix: str, depth: int) -> Artifact:
        path = f"{prefix}{SEPARATOR if prefix else ''}{region.format}@0x{region.offset:x}"
        artifact = Artifact(path, region.format, region.kind, region.offset, region.size, region.description)
        if region.kind is FormatKind.IDENTIFIED:
            artifact.signing = self._facts(buffer, region)
            return artifact
        unpacked = self._unpack(buffer, region, path, depth)
        if unpacked is not None:
            self._absorb(artifact, unpacked, depth)
        return artifact

    def _unpack(self, buffer: Buffer, region: Region, path: str, depth: int) -> Unpacked | None:
        try:
            self.budget.check_depth(depth + 1)
            return self.formats[region.format].unpack(memoryview(buffer), region, self.budget)
        except BudgetExceeded as error:
            self._notice("budget-exceeded", str(error), path)
        except MissingExtra as error:
            self._notice("missing-extra", str(error), path)
        except FormatError as error:
            self.undecodable.add(path)
            self._notice("unpack-failed", str(error), path)
        if region.kind in (FormatKind.CONTAINER, FormatKind.FILESYSTEM):
            self.failed.add(path)
        return None

    def _facts(self, buffer: Buffer, region: Region) -> Signing | None:
        try:
            return self.formats[region.format].unpack(memoryview(buffer), region, self.budget).signing
        except (FormatError, BudgetExceeded, MissingExtra):
            return None

    def _absorb(self, artifact: Artifact, unpacked: Unpacked, depth: int) -> None:
        artifact.signing = unpacked.signing
        if unpacked.consumed is not None and artifact.size is None:
            artifact.size = unpacked.consumed
        self.result.notices.extend(unpacked.notices)
        if not unpacked.checksum_ok:
            self._checksum_finding(artifact)
        if unpacked.filesystem is not None:
            artifact.file_count = unpacked.filesystem.file_count
            self.result.filesystems.append(Located(artifact.path, unpacked.filesystem))
            artifact.children.extend(self._search_filesystem(unpacked.filesystem, artifact.path, depth + 1))
        for stream in unpacked.streams:
            artifact.children.extend(self._stream(artifact, stream, depth))

    def _stream(self, parent: Artifact, stream: Stream, depth: int) -> list[Artifact]:
        if parent.kind is FormatKind.COMPRESSION:
            return self._scan(stream.data, parent.path, depth + 1, entropy=False)
        path = f"{parent.path}{SEPARATOR}{stream.name}"
        node = Artifact(path, stream.name, FormatKind.STREAM, stream.offset, len(stream.data), stream.description)
        node.children = self._scan(stream.data, path, depth + 1)
        return [node]

    def _search_filesystem(self, filesystem: Filesystem, prefix: str, depth: int) -> list[Artifact]:
        nodes: list[Artifact] = []
        for entry in filesystem.files():
            if not self._worth_scanning(filesystem, entry.data):
                continue
            path = f"{prefix}{SEPARATOR}{entry.path}"
            try:
                self.budget.check_depth(depth + 1)
            except BudgetExceeded as error:
                self._notice("budget-exceeded", str(error), path)
                continue
            node = Artifact(path, "file", FormatKind.STREAM, 0, entry.size)
            node.children = self._scan(entry.data, path, depth + 1)
            nodes.append(node)
        return nodes

    def _worth_scanning(self, filesystem: Filesystem, data: bytes) -> bool:
        """Every member of a package (tar, zip) is an image to scan; in a root filesystem only a
        large file that starts like an image is, so ordinary files are not searched for magics."""
        if filesystem.package:
            return bool(data)
        return len(data) >= NESTED_MINIMUM and self._starts_with_image(data)

    def _starts_with_image(self, data: bytes) -> bool:
        view = memoryview(data)
        candidates = (f for f in self.formats.values() if f.kind in (FormatKind.CONTAINER, FormatKind.FILESYSTEM))
        return any(_probes_at_start(fmt, data, view) for fmt in candidates)

    def _flag_unidentified(self, buffer: Buffer, artifacts: list[Artifact], regions: list[Region], label: str) -> None:
        view = memoryview(buffer)
        runs = [run for start, end in _gaps(len(buffer), artifacts, regions) for run in _high_runs(view, start, end)]
        if runs:
            self._entropy_finding(label, runs)

    def _entropy_finding(self, label: str, runs: list[tuple[int, int]]) -> None:
        """One finding per buffer: many spans are one fact (often a format split by headers)."""
        total = sum(end - start for start, end in runs)
        start, end = runs[0]
        spans = ", ".join(f"0x{a:x}–0x{b:x}" for a, b in runs[:LISTED_SPANS])
        more = f" and {len(runs) - LISTED_SPANS} more" if len(runs) > LISTED_SPANS else ""
        title = f"{total:,} bytes of high-entropy data with no recognized format" + (
            f" in {len(runs)} spans" if len(runs) > 1 else ""
        )
        evidence = Evidence(
            f"{spans}{more}; entropy above {ENTROPY_THRESHOLD} bits/byte",
            f"dd if=IMAGE bs=1 skip={start} count={end - start} | xxd | head",
        )
        self.result.findings.append(
            Finding("FWT-IMG-001", title, Severity.INFO, Confidence.INDICATOR, Location(label, offset=start), evidence)
        )

    def _checksum_finding(self, artifact: Artifact) -> None:
        self.result.findings.append(
            Finding(
                "FWT-IMG-002",
                f"{artifact.format} payload checksum does not match its header",
                Severity.LOW,
                Confidence.CONFIRMED,
                Location(artifact.path, offset=artifact.offset),
                Evidence(
                    f"{artifact.format} header at 0x{artifact.offset:x}: data checksum mismatch",
                    "fwtriage scan IMAGE --json report.json",
                ),
            )
        )

    def _notice(self, code: str, message: str, location: str) -> None:
        self.result.notices.append(Notice(code, message, location))


def _probes_at_start(fmt: Format, data: bytes, view: memoryview) -> bool:
    if not any(data.startswith(magic) and position == 0 for magic, position in fmt.magics):
        return False
    try:
        return fmt.probe(view, 0) is not None
    except FormatError:
        return False


def unattributed(
    view: memoryview, artifacts: list[Artifact], failed: AbstractSet[str] = frozenset()
) -> tuple[int, tuple[int, int]]:
    """Bytes outside every top-level artifact that are not padding, and the largest such span (F24).
    A region that failed to unpack was not understood, so it does not count as covered."""
    covered = sorted((a.offset, a.offset + a.size) for a in artifacts if a.size and a.path not in failed)
    unknown, largest, cursor = 0, (0, 0), 0
    for start, end in [*covered, (len(view), len(view))]:
        if start > cursor:
            count, span = _non_padding(view, cursor, start)
            unknown += count
            largest = max(largest, span, key=lambda s: s[1] - s[0])
        cursor = max(cursor, end)
    return unknown, largest


def _non_padding(view: memoryview, start: int, end: int) -> tuple[int, tuple[int, int]]:
    """Non-padding bytes in a gap, and the span from the first to the last block that holds any."""
    blocks = [b for b in range(start, end, PADDING_BLOCK) if not is_uniform(view[b : min(b + PADDING_BLOCK, end)])]
    if not blocks:
        return 0, (0, 0)
    count = sum(min(PADDING_BLOCK, end - b) for b in blocks)
    return count, (blocks[0], min(blocks[-1] + PADDING_BLOCK, end))


def _high_runs(view: memoryview, start: int, end: int) -> list[tuple[int, int]]:
    """Maximal runs of high-entropy blocks inside a gap, at least ENTROPY_SPAN long (F6)."""
    runs: list[tuple[int, int]] = []
    run_start: int | None = None
    for block in range(start, end, ENTROPY_SPAN):
        block_end = min(block + ENTROPY_SPAN, end)
        high = is_high(view[block:block_end], ENTROPY_THRESHOLD)
        if high and run_start is None:
            run_start = block
        if not high and run_start is not None:
            runs.append((run_start, block))
            run_start = None
    if run_start is not None:
        runs.append((run_start, end))
    return [(a, b) for a, b in runs if b - a >= ENTROPY_SPAN]


def _gaps(length: int, artifacts: list[Artifact], regions: list[Region]) -> list[tuple[int, int]]:
    starts = sorted(r.offset for r in regions)
    spans = []
    for artifact in artifacts:
        end = (
            artifact.offset + artifact.size
            if artifact.size
            else next((s for s in starts if s > artifact.offset), length)
        )
        spans.append((artifact.offset, end))
    gaps, cursor = [], 0
    for start, end in sorted(spans):
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < length:
        gaps.append((cursor, length))
    return gaps
