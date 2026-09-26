import os
import subprocess
import sys
from pathlib import Path

from tests.corpus.scenarios import SCENARIOS

SCRIPT = """
import sys
from pathlib import Path
from fwtriage.app import scan
from fwtriage.output import json_report, sarif, sbom, svg_map
image = Path(sys.argv[1])
report = scan(image)
for render in (json_report.render, sarif.render, sbom.render):
    sys.stdout.write(render(report))
sys.stdout.write(svg_map.render(image, report))
"""


def _run(image: Path, seed: str) -> str:
    environment = {**os.environ, "PYTHONHASHSEED": seed}
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT, str(image)], env=environment, capture_output=True, text=True, check=True
    )
    return result.stdout


def test_two_runs_with_different_hash_seeds_are_identical(tmp_path: Path) -> None:
    for scenario in (s for s in SCENARIOS if s.name in ("exposed", "nested", "damaged")):
        image = tmp_path / f"{scenario.name}.bin"
        image.write_bytes(scenario.build())
        assert _run(image, "1") == _run(image, "4242"), f"R5: {scenario.name} output differs between runs"
