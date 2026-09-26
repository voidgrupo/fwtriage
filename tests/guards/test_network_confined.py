from .source import imports, modules

NETWORK = ("socket", "ssl", "http", "urllib.request", "urllib.error", "ftplib", "smtplib", "asyncio")
ALLOWED = "fwtriage/vulns/nvd.py"


def test_only_the_nvd_client_imports_networking() -> None:
    offenses = [
        f"{module.relative}:{line} imports {name}"
        for module in modules()
        if module.relative != ALLOWED
        for name, line in imports(module)
        if name == "urllib.request" or name.startswith(NETWORK)
    ]
    assert not offenses, f"R2: network code lives only in {ALLOWED}.\n" + "\n".join(offenses)
