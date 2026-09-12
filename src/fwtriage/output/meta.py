from importlib import metadata


def tool_version() -> str:
    try:
        return metadata.version("fwtriage")
    except metadata.PackageNotFoundError:
        return "0+unknown"
