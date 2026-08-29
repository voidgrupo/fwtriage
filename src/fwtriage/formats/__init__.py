from .base import Format
from .compression import Bzip2, Gzip, LzmaAlone, Xz, Zstd
from .fit import DeviceTree, Fit
from .identified import Elf, Pem
from .squashfs import Squashfs
from .trx import Trx
from .uimage import UImage

REGISTRY: tuple[Format, ...] = (
    UImage(),
    Fit(),
    Trx(),
    Squashfs(),
    Gzip(),
    Xz(),
    LzmaAlone(),
    Bzip2(),
    Zstd(),
    Elf(),
    DeviceTree(),
    Pem(),
)

__all__ = ["REGISTRY", "Format"]
