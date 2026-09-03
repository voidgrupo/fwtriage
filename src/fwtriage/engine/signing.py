import re

from fwtriage.model import Artifact, Confidence, Evidence, Finding, FormatKind, Location, Signature, lookup

WEAK_HASHES = ("sha1", "md5")
RSA_BITS = re.compile(r"rsa(\d+)")
MINIMUM_RSA = 2048
FIRMWARE_KINDS = (FormatKind.CONTAINER, FormatKind.FILESYSTEM)


def judge(artifacts: list[Artifact], image: str, unsure: bool = False) -> list[Finding]:
    """Signing findings for one image (F23), from the facts its containers declared. When part of
    the image was not understood, the absence of a signature is not asserted (`unsure`)."""
    nodes = [node for root in artifacts for node in root.walk()]
    findings = [finding for node in nodes for finding in _per_artifact(node)]
    unsigned = None if unsure else _unsigned(nodes, image)
    return findings + ([unsigned] if unsigned else [])


def would_flag_unsigned(artifacts: list[Artifact]) -> bool:
    return _unsigned([node for root in artifacts for node in root.walk()], "") is not None


def _per_artifact(node: Artifact) -> list[Finding]:
    signing = node.signing
    if signing is None:
        return []
    weak = [item for item in (*signing.signatures, *signing.keys) if is_weak(item)]
    findings = [_weak(node, weak)] if weak else []
    findings += _image_only(node) + _partial_configurations(node) + _optional_keys(node)
    return findings


def is_weak(item: Signature) -> bool:
    algorithm = item.algorithm.lower()
    bits = RSA_BITS.search(algorithm)
    short_key = item.bits is not None and item.bits < MINIMUM_RSA
    return (
        any(weak in algorithm for weak in WEAK_HASHES)
        or short_key
        or (bits is not None and int(bits.group(1)) < MINIMUM_RSA)
    )


def _weak(node: Artifact, items: list[Signature]) -> Finding:
    """One finding per artifact, listing every weak signature or key it declares."""
    described = [
        f"{item.node}: {item.algorithm or 'rsa'}{f', {item.bits}-bit key' if item.bits else ''}" for item in items
    ]
    algorithms = ", ".join(sorted({item.algorithm or f"rsa {item.bits}-bit" for item in items}))
    noun = "signature or key" if len(items) == 1 else "signatures and keys"
    return _finding("FWT-SIG-002", f"{len(items)} weak {noun} ({algorithms})", node, "; ".join(described))


def _image_only(node: Artifact) -> list[Finding]:
    signing = node.signing
    assert signing is not None
    scopes = {item.scope for item in signing.signatures}
    if scopes != {"image"}:
        return []
    signed = ", ".join(item.node for item in signing.signatures)
    return [_finding("FWT-SIG-003", "signatures cover images, not configurations", node, f"signed: {signed}")]


def _partial_configurations(node: Artifact) -> list[Finding]:
    signing = node.signing
    assert signing is not None
    loaded = dict(signing.loaded)
    findings = []
    for item in signing.signatures:
        configuration = item.node.split("/", 1)[0]
        if item.scope != "configuration" or "(default)" in item.covers:
            continue
        missing = sorted(set(loaded.get(configuration, ())) - set(item.covers))
        if missing:
            excerpt = f"{item.node}: sign-images = {', '.join(item.covers)}; also loads {', '.join(missing)}"
            findings.append(
                _finding("FWT-SIG-004", f"{configuration} loads unsigned {', '.join(missing)}", node, excerpt)
            )
    return findings


def _optional_keys(node: Artifact) -> list[Finding]:
    signing = node.signing
    assert signing is not None
    if not signing.keys or any(key.required for key in signing.keys):
        return []
    names = ", ".join(f"{key.key} ({key.algorithm or 'rsa'})" for key in signing.keys)
    return [
        _finding("FWT-SIG-005", "verification keys present, none required", node, f"keys without 'required': {names}")
    ]


def _unsigned(nodes: list[Artifact], image: str) -> Finding | None:
    if not any(node.kind in FIRMWARE_KINDS for node in nodes):
        return None
    if any(node.signing and node.signing.signatures for node in nodes):
        return None
    offered = [f"{node.path}: {', '.join(node.signing.integrity) or 'nothing'}" for node in nodes if node.signing]
    excerpt = "; ".join(offered) if offered else "no container with integrity data"
    location = Location(image)
    evidence = Evidence(excerpt, "fwtriage scan IMAGE --json report.json  # artifacts[].signing")
    return Finding(
        "FWT-SIG-001",
        "no signature found in the image",
        lookup("FWT-SIG-001").severity,
        Confidence.LIKELY,
        location,
        evidence,
    )


def _finding(rule: str, title: str, node: Artifact, excerpt: str) -> Finding:
    location = Location(node.path)
    evidence = Evidence(excerpt, "fwtriage scan IMAGE --json report.json  # artifacts[].signing")
    return Finding(rule, title, lookup(rule).severity, Confidence.CONFIRMED, location, evidence)
