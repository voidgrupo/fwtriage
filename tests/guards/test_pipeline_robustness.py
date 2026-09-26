from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fwtriage.analyzers import Context
from fwtriage.app import _run_analyzer, scan
from fwtriage.engine import Result
from fwtriage.model import Filesystem, Limits, Policy
from fwtriage.model.budget import MIB
from fwtriage.output import json_report, sarif, sbom
from tests.corpus.scenarios import SCENARIOS, clean_tree, exposed_tree
from tests.corpus.writers import cpio, cramfs, jffs2, squashfs

SEEDS = {s.name: s.build() for s in SCENARIOS if s.name != "bomb"} | {
    "squashfs": squashfs.write(exposed_tree()),
    "cramfs": cramfs.write(clean_tree(), order=">"),
    "jffs2": jffs2.write(exposed_tree(), compression="rtime"),
    "cpio": cpio.write(exposed_tree(), crc=True),
}
SMALL = Policy(limits=Limits(entry_bytes=8 * MIB, total_bytes=32 * MIB))
EDITS = st.lists(st.tuples(st.integers(min_value=0), st.integers(min_value=0, max_value=255)), min_size=1, max_size=8)


def _mutate(seed: bytes, edits: list[tuple[int, int]], cut: int) -> bytes:
    data = bytearray(seed)
    for position, value in edits:
        data[position % len(data)] = value
    return bytes(data[: max(1, len(data) - cut)])


@settings(
    max_examples=400, deadline=3000, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture]
)
@given(seed=st.sampled_from(sorted(SEEDS)), edits=EDITS, cut=st.integers(min_value=0, max_value=64))
def test_whole_pipeline_survives_mutated_images(
    tmp_path: Path, seed: str, edits: list[tuple[int, int]], cut: int
) -> None:
    image = tmp_path / "mutated.bin"
    image.write_bytes(_mutate(SEEDS[seed], edits, cut))
    report = scan(image, SMALL)
    for render in (json_report.render, sarif.render, sbom.render):
        render(report)
    failed = [notice.message for notice in report.notices if notice.code == "analyzer-failed"]
    assert not failed, f"an analyzer raised on hostile input: {failed}"


def test_a_failing_analyzer_becomes_a_notice() -> None:
    class Broken:
        area = "XXX"

        def analyze(self, context: Context) -> None:
            raise OverflowError("boom")

    result = Result()
    analysis = _run_analyzer(Broken(), Context(Filesystem("t"), "fs"), result)  # type: ignore[arg-type]
    assert analysis.findings == []
    assert [(n.code, n.location) for n in result.notices] == [("analyzer-failed", "fs")]


@pytest.mark.parametrize("seed", sorted(SEEDS))
def test_every_truncation_of_small_seeds(tmp_path: Path, seed: str) -> None:
    data = SEEDS[seed]
    if len(data) > 5000:
        pytest.skip("covered by sampling above")
    image = tmp_path / "cut.bin"
    for end in range(0, len(data), 7):
        image.write_bytes(data[:end])
        report = scan(image, SMALL)
        assert not [n for n in report.notices if n.code == "analyzer-failed"], (seed, end)
