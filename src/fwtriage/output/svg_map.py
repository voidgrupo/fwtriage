import math
from html import escape
from pathlib import Path

from fwtriage.model import Artifact, Report
from fwtriage.model.entropy import sampled

COLUMNS = 96
TARGET_ROWS = 64
CELL = 6
GAP = 1
LABEL_WIDTH = 380
PALETTE = ((129, 140, 248), (45, 212, 191), (244, 114, 182), (251, 191, 36), (163, 230, 53))
NEUTRAL = (228, 228, 240)
PADDING = "#0d0d0f"
FONT = "ui-monospace,SFMono-Regular,Menlo,monospace"


def render(image: Path, report: Report) -> str:
    size = image.stat().st_size
    block = max(1, math.ceil(size / (COLUMNS * TARGET_ROWS)))
    values = _profile(image, block)
    spans = [a for a in report.artifacts if a.size]
    rows = max(1, math.ceil(len(values) / COLUMNS))
    cells = "".join(_cell(index, value, _hue(index * block, spans)) for index, value in enumerate(values))
    labels = "".join(_label(a, block, rows, PALETTE[i % len(PALETTE)]) for i, a in enumerate(spans))
    legend = (
        f'<text x="0" y="{rows * CELL + 28}" class="legend">{escape(report.image.name)} · 1 cell = {block:,} bytes'
        " · dark = padding · bright = compressed or encrypted (sampled)</text>"
    )
    return _document(COLUMNS * CELL + LABEL_WIDTH, rows * CELL + 40, cells + labels + legend)


def _profile(image: Path, block: int) -> list[float | None]:
    values: list[float | None] = []
    with image.open("rb") as handle:
        while chunk := handle.read(block):
            values.append(sampled(chunk))
    return values


def _hue(offset: int, spans: list[Artifact]) -> tuple[int, int, int]:
    index = next((i for i, a in enumerate(spans) if a.offset <= offset < a.offset + (a.size or 0)), None)
    return NEUTRAL if index is None else PALETTE[index % len(PALETTE)]


def _cell(index: int, value: float | None, hue: tuple[int, int, int]) -> str:
    x, y = index % COLUMNS * CELL, index // COLUMNS * CELL
    return f'<rect x="{x}" y="{y}" width="{CELL - GAP}" height="{CELL - GAP}" fill="{_color(value, hue)}"/>'


def _color(value: float | None, hue: tuple[int, int, int]) -> str:
    if value is None:
        return PADDING
    level = 0.12 + (value / 8) ** 2.2 * 0.88
    red, green, blue = (round(channel * level) for channel in hue)
    return f"#{red:02x}{green:02x}{blue:02x}"


def _label(artifact: Artifact, block: int, rows: int, hue: tuple[int, int, int]) -> str:
    top = artifact.offset // block // COLUMNS * CELL
    bottom = min(rows, math.ceil((artifact.offset + (artifact.size or 0)) / block / COLUMNS)) * CELL
    x = COLUMNS * CELL + 12
    color = "#{:02x}{:02x}{:02x}".format(*hue)
    detail = escape(artifact.description[:52])
    return (
        f'<path d="M{x} {top + 2}h6v{max(4, bottom - top - 4)}h-6" class="bracket" stroke="{color}"/>'
        f'<text x="{x + 14}" y="{top + 10}" class="title" fill="{color}">{escape(artifact.path)}</text>'
        f'<text x="{x + 14}" y="{top + 24}" class="detail">{detail}</text>'
    )


def _document(width: int, height: int, body: str) -> str:
    style = (
        ".bracket{fill:none;stroke-width:1.5}"
        f".title{{font:600 11px {FONT}}}"
        f".detail{{fill:#a1a1aa;font:11px {FONT}}}"
        f".legend{{fill:#71717a;font:11px {FONT}}}"
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="-12 -12 {width + 24} {height + 12}" width="{width + 24}">'
        f'<rect x="-12" y="-12" width="{width + 24}" height="{height + 12}" fill="#000"/>'
        f"<style>{style}</style>{body}</svg>\n"
    )
