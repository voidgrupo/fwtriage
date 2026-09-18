import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from fwtriage.model import OnlineError

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 60
PAUSE_WITH_KEY = 0.7
PAUSE_WITHOUT_KEY = 6.5

Transport = Callable[[str, dict[str, str]], bytes]


def http_transport(url: str, headers: dict[str, str]) -> bytes:
    request = urllib.request.Request(url, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            return bytes(response.read())
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise OnlineError(f"NVD request failed: {error}") from error


class Client:
    """Queries NVD by CPE; the only code that reaches the network (R2)."""

    def __init__(self, api_key: str | None = None, transport: Transport = http_transport, pause: bool = True) -> None:
        self.api_key = api_key
        self.transport = transport
        self.pause = pause
        self._last = 0.0

    def query(self, cpe: str, limit: int) -> dict[str, Any]:
        self._wait()
        parameters = urllib.parse.urlencode({"virtualMatchString": cpe, "resultsPerPage": limit})
        headers = {"apiKey": self.api_key} if self.api_key else {}
        body = self.transport(f"{ENDPOINT}?{parameters}", headers)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as error:
            raise OnlineError(f"NVD returned invalid JSON for {cpe}") from error
        if not isinstance(payload, dict) or "totalResults" not in payload:
            raise OnlineError(f"NVD returned an unexpected document for {cpe}")
        return payload

    def _wait(self) -> None:
        if not self.pause:
            return
        interval = PAUSE_WITH_KEY if self.api_key else PAUSE_WITHOUT_KEY
        remaining = self._last + interval - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        self._last = time.monotonic()
