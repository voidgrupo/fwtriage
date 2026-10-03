from .archives import Tar, Zip
from .base import Format
from .compression import Bzip2, Gzip, LzmaAlone, Xz, Zstd
from .cpio import Cpio
from .cramfs import Cramfs
from .fit import DeviceTree, Fit
from .fwtool import Fwtool
from .identified import Elf, Pem
from .jffs2 import Jffs2
from .squashfs import Squashfs
from .trx import Trx
from .ubi import Ubi
from .uimage import UImage
from .vendor import MikrotikNpk, NetgearChk, ReolinkPak, TplinkSafeloader, XiaomiHdr1

REGISTRY: tuple[Format, ...] = (
    TplinkSafeloader(),
    XiaomiHdr1(),
    MikrotikNpk(),
    NetgearChk(),
    ReolinkPak(),
    UImage(),
    Fit(),
    Trx(),
    Ubi(),
    Squashfs(),
    Cramfs(),
    Jffs2(),
    Cpio(),
    Tar(),
    Zip(),
    Gzip(),
    Xz(),
    LzmaAlone(),
    Bzip2(),
    Zstd(),
    Elf(),
    DeviceTree(),
    Fwtool(),
    Pem(),
)

__all__ = ["REGISTRY", "Format"]
