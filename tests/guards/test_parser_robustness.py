import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fwtriage.formats import REGISTRY
from fwtriage.formats.base import Format
from fwtriage.model import Budget, BudgetExceeded, FormatError, Limits, MissingExtra
from fwtriage.model.budget import MIB
from tests.corpus.scenarios import SCENARIOS

ACCEPTED = (FormatError, BudgetExceeded, MissingExtra)
SMALL = Limits(total_bytes=16 * MIB, entry_bytes=4 * MIB, depth=4, entries=2000)
SEEDS = {scenario.name: scenario.build() for scenario in SCENARIOS if scenario.name != "bomb"}


def exercise(fmt: Format, data: bytes) -> None:
    view = memoryview(data)
    for magic, position in fmt.magics:
        found = data.find(magic)
        if found < position:
            continue
        try:
            region = fmt.probe(view, found - position)
            if region is not None:
                fmt.unpack(view, region, Budget(SMALL))
        except ACCEPTED:
            continue


def mutate(seed: bytes, edits: list[tuple[int, int]]) -> bytes:
    data = bytearray(seed)
    for position, value in edits:
        data[position % len(data)] = value
    return bytes(data)


@pytest.mark.parametrize("fmt", REGISTRY, ids=lambda f: f.name)
@settings(max_examples=150, deadline=2000, suppress_health_check=[HealthCheck.too_slow])
@given(tail=st.binary(max_size=4096))
def test_random_bytes_after_a_magic(fmt: Format, tail: bytes) -> None:
    for magic, position in fmt.magics:
        exercise(fmt, b"\0" * position + magic + tail)


@pytest.mark.parametrize("fmt", REGISTRY, ids=lambda f: f.name)
@settings(max_examples=60, deadline=4000, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(
    seed=st.sampled_from(sorted(SEEDS)),
    edits=st.lists(
        st.tuples(st.integers(min_value=0), st.integers(min_value=0, max_value=255)), min_size=1, max_size=24
    ),
)
def test_mutated_corpus_images(fmt: Format, seed: str, edits: list[tuple[int, int]]) -> None:
    exercise(fmt, mutate(SEEDS[seed], edits))
