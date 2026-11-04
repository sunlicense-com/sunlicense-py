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

from .analytics import SunLicenseAnalytics
from .protection import Locked, Refused, SunLicenseProtection, mask

__version__ = "0.2.0"
__all__ = ["SunLicense", "SunLicenseAnalytics", "SunLicenseProtection", "Locked", "Refused", "mask",
           "ValidationResult", "__version__"]


class ValidationResult(NamedTuple):
    """Outcome of a licence validation call.

    ``data`` is the parsed JSON body, or the body as text when it isn't JSON (for example an
    error page from a proxy in front of the API), or None when the body is empty.
    """

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
        # Without one, urllib sends "Python-urllib/3.x", which Cloudflare (in front of
        # api.sunlicense.com) refuses with 403 "error code: 1010" before the API sees it.
        self._user_agent = "sunlicense-python/" + __version__
        self._protection: Optional[SunLicenseProtection] = None

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
        # With client.protection(...): send its integrity result, then let it keep (valid + unlock) or forget
        # (valid: false) the unlock. Outages change nothing.
        protection = self._protection
        if protection is not None:
            protection.license(license_key, context.get("fingerprint") or context.get("hwid") or context.get("host")
                               or protection.fingerprint)
            for k, v in protection.validate_fields().items():
                payload.setdefault(k, v)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self._user_agent,
        }
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
                result = ValidationResult(
                    valid=200 <= response.status < 300,
                    status=response.status,
                    data=_maybe_json(body),
                )
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            result = ValidationResult(valid=False, status=error.code, data=_maybe_json(body))
        if protection is not None:
            protection.accept(result.data)
        return result

    def protection(self, **options: Any) -> SunLicenseProtection:
        """Core unlock, tamper reports, the ownership notice and protected files, with this client's base URL and API
        key (see :class:`SunLicenseProtection`). Every later :meth:`validate` sends its integrity result and keeps or
        forgets the unlock.

        Args:
            **options: ``license_key``, ``fingerprint``, ``product``, ``owner``, ``terms``, ``product_code``,
                ``cache_directory``.
        """
        options.setdefault("base_url", self.base_url)
        options.setdefault("api_key", self.token)
        options.setdefault("user_agent", self._user_agent)
        self._protection = SunLicenseProtection(**options)
        return self._protection

    def analytics(self, license_key: Any = None, fingerprint: Optional[str] = None, **options: Any) -> SunLicenseAnalytics:
        """Starts built-in product analytics for a licensed product, with this client's base URL and API key:
        a report every 30 minutes on a background thread (see :class:`SunLicenseAnalytics`). Never raises.

        Args:
            license_key: The license key you validate (or a callable returning it).
            fingerprint: The machine id you validate with (``host``).
            **options: Any :class:`SunLicenseAnalytics` option (``product_version``, ``enabled``,
                ``product_analytics_id``, ``data_directory``, ...).
        """
        options.setdefault("base_url", self.base_url)
        options.setdefault("api_key", self.token)
        return SunLicenseAnalytics.start(license_key=license_key, fingerprint=fingerprint, **options)

    @staticmethod
    def analytics_for(product_analytics_id: str, **options: Any) -> SunLicenseAnalytics:
        """Starts built-in product analytics for a free product with its public product analytics id
        (Product -> Analytics in the dashboard). No license or API key needed. Never raises."""
        return SunLicenseAnalytics.start(product_analytics_id=product_analytics_id, **options)


def _maybe_json(body: str) -> Optional[Any]:
    """Parse *body* as JSON; return it as text when it isn't JSON, None when it's empty."""
    if not body.strip():
        return None
    try:
        return json.loads(body)
    except ValueError:
        return body
