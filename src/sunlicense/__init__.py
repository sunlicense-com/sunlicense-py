"""SunLicense — official Python client.

Early release. Licence validation works against the SunLicense REST API; the wider
client surface (activations, entitlements, offline verification) is in development.

Docs: https://docs.sunlicense.hapangama.com
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, NamedTuple, Optional

__version__ = "0.0.1"
__all__ = ["SunLicense", "ValidationResult", "__version__"]


class ValidationResult(NamedTuple):
    """Outcome of a licence validation call."""

    valid: bool
    status: int
    data: Optional[Any]


class SunLicense:
    """A SunLicense API client.

    Example:
        >>> client = SunLicense(base_url="https://your-instance.example.com")
        >>> result = client.validate("LICENCE-KEY-HERE")
        >>> if result.valid:
        ...     print("ok")
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        """
        Args:
            base_url: Base URL of your SunLicense instance.
            token: API token, if your endpoint requires one.
            timeout: Request timeout in seconds.
        """
        if not base_url:
            raise ValueError('SunLicense: "base_url" is required')
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def validate(
        self,
        license_key: str,
        **context: Any,
    ) -> ValidationResult:
        """Validate a licence key.

        Args:
            license_key: The licence key to check.
            **context: Optional extra fields, e.g. ``product=...``, ``host=...``.

        Returns:
            A :class:`ValidationResult`.

        Raises:
            ValueError: If ``license_key`` is empty.
            urllib.error.URLError: On network failure.
        """
        if not license_key:
            raise ValueError('SunLicense: "license_key" is required')

        payload: Dict[str, Any] = {"license": license_key, **context}
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token

        request = urllib.request.Request(
            self.base_url + "/api/v2/license/validate",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                return ValidationResult(
                    valid=200 <= response.status < 300,
                    status=response.status,
                    data=_maybe_json(body),
                )
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            return ValidationResult(valid=False, status=error.code, data=_maybe_json(body))


def _maybe_json(body: str) -> Optional[Any]:
    """Parse *body* as JSON, returning None when it isn't valid JSON."""
    try:
        return json.loads(body)
    except ValueError:
        return None
