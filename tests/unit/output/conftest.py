from pathlib import Path

import pytest

from fwtriage.app import scan
from fwtriage.model import Report
from tests.corpus.scenarios import SCENARIOS


@pytest.fixture(scope="module")
def exposed(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Report]:
    scenario = next(s for s in SCENARIOS if s.name == "exposed")
    image = tmp_path_factory.mktemp("img") / "exposed.bin"
    image.write_bytes(scenario.build())
    return image, scan(image)
