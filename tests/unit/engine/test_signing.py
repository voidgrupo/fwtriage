import pytest

from fwtriage.engine.signing import is_weak, judge
from fwtriage.model import Artifact, FormatKind, Signature, Signing


def node(path: str, signing: Signing | None, kind: FormatKind = FormatKind.CONTAINER) -> Artifact:
    artifact = Artifact(path, path.split("@", maxsplit=1)[0], kind, 0, 100)
    artifact.signing = signing
    return artifact


def rules(artifacts: list[Artifact]) -> list[str]:
    return sorted(finding.rule for finding in judge(artifacts, "image.bin"))


@pytest.mark.parametrize(
    ("algorithm", "bits", "weak"),
    [
        ("sha256,rsa2048", None, False),
        ("sha256,rsa4096", 4096, False),
        ("sha1,rsa2048", None, True),
        ("md5,rsa2048", None, True),
        ("sha256,rsa1024", None, True),
        ("sha256,rsa2048", 1024, True),
        ("sha256,ecdsa256", None, False),
    ],
)
def test_weak_algorithms_and_keys(algorithm: str, bits: int | None, weak: bool) -> None:
    assert is_weak(Signature("n", algorithm, bits=bits)) is weak


def test_unsigned_image_names_what_each_container_offers() -> None:
    findings = judge(
        [node("uimage@0x0", Signing(integrity=("crc32",))), node("squashfs@0x40", None, FormatKind.FILESYSTEM)],
        "fw.bin",
    )
    assert [(f.rule, f.confidence.label) for f in findings] == [("FWT-SIG-001", "likely")]
    assert findings[0].evidence.excerpt == "uimage@0x0: crc32"


def test_a_bare_stream_is_not_judged_as_firmware() -> None:
    assert rules([node("bzip2@0x0", None, FormatKind.COMPRESSION)]) == []


def test_configuration_signature_covering_everything_is_clean() -> None:
    signature = Signature("conf-1/signature-1", "sha256,rsa2048", "dev", ("kernel", "fdt"), "configuration")
    signing = Signing(("sha256",), (signature,), (), (("conf-1", ("kernel", "fdt")),))
    assert rules([node("fit@0x0", signing)]) == []


def test_default_sign_images_is_not_judged() -> None:
    signature = Signature("conf-1/signature-1", "sha256,rsa2048", "dev", ("(default)",), "configuration")
    signing = Signing((), (signature,), (), (("conf-1", ("kernel", "fdt", "ramdisk")),))
    assert rules([node("fit@0x0", signing)]) == []


def test_required_key_is_clean_and_optional_key_is_reported() -> None:
    required = Signing(keys=(Signature("signature/key-a", "sha256,rsa2048", "a", (), "conf", True, 2048),))
    optional = Signing(keys=(Signature("signature/key-a", "sha256,rsa2048", "a", (), "none", False, 2048),))
    assert "FWT-SIG-005" not in rules([node("dtb@0x0", required, FormatKind.IDENTIFIED)])
    assert "FWT-SIG-005" in rules([node("dtb@0x0", optional, FormatKind.IDENTIFIED)])


def test_whole_file_signature_satisfies_the_image() -> None:
    signature = Signature("fwtool/signature", "usign ed25519", "", ("whole image",), "file")
    tree = [
        node("uimage@0x0", Signing(integrity=("crc32",))),
        node("fwtool@0x99", Signing(("fwtool",), (signature,)), FormatKind.IDENTIFIED),
    ]
    assert rules(tree) == []
