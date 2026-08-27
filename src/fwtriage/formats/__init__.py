from .base import Format
from .compression import Bzip2, Gzip, LzmaAlone, Xz, Zstd
from .identified import Elf, Pem
from .squashfs import Squashfs

REGISTRY: tuple[Format, ...] = (
    Squashfs(),
    Gzip(),
    Xz(),
    LzmaAlone(),
    Bzip2(),
    Zstd(),
    Elf(),
    Pem(),
)

__all__ = ["REGISTRY", "Format"]
