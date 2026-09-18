from fwtriage.model import Component, Finding

from .cache import Cache
from .matcher import Matcher
from .nvd import Client


def match(components: list[Component]) -> list[Finding]:
    return Matcher().run(components)


__all__ = ["Cache", "Client", "Matcher", "match"]
