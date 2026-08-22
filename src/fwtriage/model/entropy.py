import math
from collections import Counter


def shannon(chunk: bytes | memoryview) -> float:
    """Shannon entropy in bits per byte, 0.0 for an empty chunk."""
    data = bytes(chunk)
    if not data:
        return 0.0
    total = len(data)
    return -sum(count / total * math.log2(count / total) for count in Counter(data).values())


def is_uniform(chunk: bytes | memoryview) -> bool:
    data = bytes(chunk)
    return bool(data) and data.count(data[:1]) == len(data)


SAMPLE = 4096


def is_high(chunk: bytes | memoryview, threshold: float) -> bool:
    """Cheap test first: one repeated byte is never high, a low-entropy sample rejects early."""
    data = bytes(chunk)
    if not data or is_uniform(data):
        return False
    if len(data) > SAMPLE and shannon(data[:SAMPLE]) < threshold - 0.5:
        return False
    return shannon(data) > threshold


def sampled(chunk: bytes | memoryview) -> float | None:
    """Entropy of at most SAMPLE bytes; None for padding. Good enough to draw, not to judge."""
    data = bytes(chunk[:SAMPLE])
    return None if is_uniform(chunk) else shannon(data)


def profile(data: bytes | memoryview, block_size: int) -> list[float | None]:
    """Entropy per block; None marks a block made of one repeated byte (padding)."""
    view = memoryview(data)
    blocks = (view[start : start + block_size] for start in range(0, len(view), block_size))
    return [None if is_uniform(block) else shannon(block) for block in blocks]
