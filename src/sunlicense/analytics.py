"""Built-in product analytics.

Every 30 minutes, on a background daemon thread, this install tells SunLicense its product version, OS,
architecture, CPU cores, locale, Python version and platform (a Discord bot or standalone). Sellers see the
totals on the product's Analytics tab.

Example::

    # A licensed product: the same API key, license key and machine id it validates with.
    analytics = client.analytics(license_key=key, fingerprint=machine_id, product_version="2.3.1",
                                 enabled=config.get("analytics", True))
    # A free product: its public product analytics id (Product -> Analytics), no license needed.
    analytics = SunLicense.analytics("pa_7Hk2mQ9xZr4LbN8vT1wYcD", data_directory="data")
    # On shutdown:
    analytics.close()

It never blocks, delays or fails a license check and never raises: errors are swallowed. Nothing is sent
while the product's ``enabled`` switch is off or the environment variable ``SUNLICENSE_ANALYTICS`` is
``off``/``false``/``0``; each is checked before every report. No personal data is sent: no user names,
host names, IP addresses, file paths or player names.
"""

from __future__ import annotations

import json
import locale
import logging
import os
import platform as _platform
import random
import re
import sys
import threading
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

__all__ = ["SunLicenseAnalytics", "SDK_NAME", "SDK_VERSION", "ENV_SWITCH"]

#: Sent as ``sdk.name``/``sdk.version``; bump the version with each release.
SDK_NAME = "python"
SDK_VERSION = "0.2.0"
DEFAULT_BASE_URL = "https://api.sunlicense.com"
#: Environment variable that switches analytics off on a machine.
ENV_SWITCH = "SUNLICENSE_ANALYTICS"

_PATH = "/api/v2/analytics/report"
INTERVAL = 30 * 60.0
MIN_WAIT = 60.0
MAX_WAIT = 24 * 3600.0
_TIMEOUT = 10.0
_MAX_BODY = 16 * 1024
_INSTALL_ID_FILE = ".sunlicense-install-id"
# Report keys every report keeps; feature usage and custom charts go first when a report is too big.
_CORE_KEYS = ("schema", "licenseKey", "fingerprint", "productAnalyticsId", "installId", "sdk", "metrics")
_INSTALL_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_OFF = {"off", "false", "0", "no", "disabled"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_LOG = logging.getLogger("sunlicense.analytics")

StrOrSupplier = Union[None, str, Callable[[], Optional[str]]]
# (status, Retry-After); status -1 = no answer
Transport = Callable[[str, Dict[str, str], bytes], Tuple[int, Optional[str]]]


class SunLicenseAnalytics:
    """One product's reporter. Use :meth:`start` (or ``client.analytics(...)`` / ``SunLicense.analytics(...)``)."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: Optional[str] = None,
        license_key: StrOrSupplier = None,
        fingerprint: Optional[str] = None,
        product_analytics_id: Optional[str] = None,
        data_directory: Optional[str] = None,
        product_version: StrOrSupplier = None,
        platform: Optional[Tuple[str, Optional[str]]] = None,
        enabled: Union[bool, Callable[[], bool]] = True,
        *,
        _env: Optional[Callable[[str], Optional[str]]] = None,
        _transport: Optional[Transport] = None,
        _random: Optional[random.Random] = None,
        _first_delay: Optional[float] = None,
        _collect: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        """
        Args:
            base_url: Defaults to https://api.sunlicense.com.
            api_key: Licensed products: the API key the product validates with (``slk_...``).
            license_key: Licensed products: the license key (a callable is read before each report).
            fingerprint: Licensed products: the machine id it validates with (``host``).
            product_analytics_id: The product's public analytics id (``pa_...``): all a free product needs.
            data_directory: Where the random install id is kept (file ``.sunlicense-install-id``).
                Defaults to ``~/.sunlicense``.
            product_version: The product's version (a callable is read before each report).
            platform: ``(name, version)`` overriding the detected platform.
            enabled: The product's own switch (or a callable read before each report); False = nothing is sent.
        """
        self._endpoint = (base_url or DEFAULT_BASE_URL).strip().rstrip("/") + _PATH
        self._api_key = clean(api_key, 512)
        self._license_key = _supplier(license_key)
        self._fingerprint = clean(fingerprint, 255)
        self._product_analytics_id = clean(product_analytics_id, 64)
        self._product_version = _supplier(product_version)
        self._platform = platform
        self._enabled = enabled if callable(enabled) else (lambda: bool(enabled))
        directory = data_directory or os.path.join(os.path.expanduser("~"), ".sunlicense")
        self._install_id_file = os.path.join(str(directory), _INSTALL_ID_FILE)
        self._env = _env or os.environ.get
        self._transport = _transport or _http_post
        self._random = _random or _random_module()
        self._first_delay = _first_delay
        self._collect = _collect
        self._sections: List[Any] = []
        self._features: Dict[str, int] = {}
        self._charts: Dict[str, Tuple[str, Callable[[], Any]]] = {}
        self._sections.append(_UsageSection(self))
        self._closed = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._metrics: Optional[Dict[str, Any]] = None
        self._install_id: Optional[str] = None
        self._last_outcome: Optional[str] = None
        self._lock = threading.Lock()

    @classmethod
    def start(cls, **options: Any) -> "SunLicenseAnalytics":
        """Starts reporting in the background (first report in 1-30 minutes). Never raises."""
        try:
            return cls(**options)._begin()
        except Exception as error:  # noqa: BLE001
            _LOG.debug("SunLicense analytics: not started: %s", error)
            return cls(enabled=False)

    def is_enabled(self) -> bool:
        """True unless the product's switch or ``SUNLICENSE_ANALYTICS`` turns it off."""
        return not self._opted_out()

    def close(self) -> None:
        """Stops reporting. Call it when the product shuts down."""
        self._closed.set()

    def send_now(self) -> int:
        """Sends one report now, on the caller's thread, and returns the HTTP status (204 = stored, 0 = nothing
        sent because analytics is off or the product isn't identified, -1 = no answer). For tests and scripts;
        a product leaves it to the schedule."""
        try:
            return self._send()[0]
        except Exception:  # noqa: BLE001
            return -1

    def feature(self, name: str, uses: int = 1) -> "SunLicenseAnalytics":
        """Counts uses of one of your product's features (``"auto-sell"``): ``uses`` (default 1) is added and
        sent with the next report, and kept until a report is stored. Cheap, thread-safe, never raises;
        nothing is counted while analytics is off. Names are lower-cased and must match
        ``[a-z0-9][a-z0-9._-]{0,47}``."""
        try:
            key = chart_id(name)
            if key and isinstance(uses, int) and not isinstance(uses, bool) and uses >= 1 and not self._closed.is_set() \
                    and not self._opted_out():
                with self._lock:
                    if key not in self._features and len(self._features) >= _MAX_FEATURES:
                        return self  # at most 50 different features
                    self._features[key] = min(_MAX_NUMBER, self._features.get(key, 0) + uses)
        except Exception:  # noqa: BLE001
            pass
        return self

    def simple_pie(self, chart: str, callback: Callable[[], Optional[str]]) -> "SunLicenseAnalytics":
        """A pie of one value per install: ``simple_pie("storage", lambda: config["storage"])``."""
        return self._chart(chart, "simple_pie", callback)

    def advanced_pie(self, chart: str, callback: Callable[[], Optional[Dict[str, int]]]) -> "SunLicenseAnalytics":
        """A pie of weighted values per install: ``advanced_pie("modules", lambda: {"shop": 1})``."""
        return self._chart(chart, "advanced_pie", callback)

    def drilldown_pie(self, chart: str, callback: Callable[[], Optional[Dict[str, Dict[str, int]]]]) -> "SunLicenseAnalytics":
        """A two-level pie: ``drilldown_pie("database", lambda: {"mysql": {"8.0": 1}})``."""
        return self._chart(chart, "drilldown_pie", callback)

    def single_line(self, chart: str, callback: Callable[[], Optional[int]]) -> "SunLicenseAnalytics":
        """A number summed over installs: ``single_line("players", lambda: len(players))``."""
        return self._chart(chart, "single_line", callback)

    def multi_line(self, chart: str, callback: Callable[[], Optional[Dict[str, int]]]) -> "SunLicenseAnalytics":
        """Several numbers per install, one line each: ``multi_line("worlds", lambda: {"overworld": 30})``."""
        return self._chart(chart, "multi_line", callback)

    def simple_bar(self, chart: str, callback: Callable[[], Optional[Dict[str, int]]]) -> "SunLicenseAnalytics":
        """Numbers per category: ``simple_bar("commands", lambda: {"sell": 12})``."""
        return self._chart(chart, "simple_bar", callback)

    def advanced_bar(self, chart: str, callback: Callable[[], Optional[Dict[str, List[int]]]]) -> "SunLicenseAnalytics":
        """Several numbers per category: ``advanced_bar("tiers", lambda: {"gold": [1, 2, 3]})``."""
        return self._chart(chart, "advanced_bar", callback)

    def remove_chart(self, chart: str) -> "SunLicenseAnalytics":
        """Stops sending a custom chart."""
        key = chart_id(chart)
        with self._lock:
            self._charts.pop(key, None)
        return self

    def _chart(self, chart: str, kind: str, callback: Any) -> "SunLicenseAnalytics":
        key = chart_id(chart)
        if not key or not callable(callback):
            self._outcome("bad-chart", "chart id %r ignored: use [a-z0-9][a-z0-9._-]{0,47} and a callable" % (chart,))
            return self
        with self._lock:
            self._charts.pop(key, None)  # the same id replaces the earlier one, at the end
            self._charts[key] = (kind, callback)
        return self

    def _add(self, section: Any) -> "SunLicenseAnalytics":
        """Something that adds to each report (feature usage, custom charts) and hears whether it was taken:
        ``write(report)`` and optionally ``sent(accepted)``."""
        self._sections.append(section)
        return self

    def _begin(self) -> "SunLicenseAnalytics":
        if not self._product_analytics_id and not (self._api_key and self._fingerprint):
            self._outcome("no-identity", "no product analytics id, and no API key and machine id: not reporting")
            return self
        first = self._first_delay if self._first_delay is not None else first_delay(self._random)
        self._thread = threading.Thread(target=self._run, args=(first,), name="SunLicense analytics", daemon=True)
        self._thread.start()
        return self

    def _run(self, delay: float) -> None:
        while not self._closed.wait(delay):
            delay = INTERVAL
            try:
                status, retry_after = self._send()
                delay = next_delay(status, retry_after)
            except Exception as error:  # noqa: BLE001
                self._outcome("error", "report failed: %s" % error)

    def _send(self) -> Tuple[int, Optional[str]]:
        if self._closed.is_set():
            return 0, None
        if self._opted_out():
            with self._lock:
                self._features.clear()  # nothing is counted while it's off
            self._outcome("off", "analytics is switched off; nothing sent")
            return 0, None
        report = self._report()
        if report is None:
            self._outcome("no-identity", "no license key yet and no product analytics id; nothing sent")
            return 0, None
        body = _json(report)
        if len(body) > _MAX_BODY and report.pop("charts", None) is not None:  # charts go first, then features
            body = _json(report)
        if len(body) > _MAX_BODY:
            for key in [k for k in report if k not in _CORE_KEYS]:
                del report[key]
            body = _json(report)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "sunlicense-%s/%s analytics" % (SDK_NAME, SDK_VERSION),
        }
        if "licenseKey" in report:
            headers["Authorization"] = "Bearer " + str(self._api_key)
        try:
            status, retry_after = self._transport(self._endpoint, headers, body)
        except Exception:  # noqa: BLE001
            status, retry_after = -1, None
        accepted = status == 204
        for section in self._sections:
            try:
                sent = getattr(section, "sent", None)
                if sent:
                    sent(accepted)
            except Exception:  # noqa: BLE001 - a section's bookkeeping never stops reporting
                pass
        if accepted:
            self._outcome("204", "report accepted")
        elif status < 0:
            self._outcome("no-answer", "SunLicense didn't answer; next report in 30 minutes")
        else:
            self._outcome("http-%d" % status, "report answered HTTP %d; next in %d s" % (status, next_delay(status, retry_after)))
        return status, retry_after

    def _opted_out(self) -> bool:
        try:
            if is_off(self._env(ENV_SWITCH)):
                return True
        except Exception:  # noqa: BLE001
            pass
        try:
            return not self._enabled()
        except Exception:  # noqa: BLE001 - a config that can't be read counts as off
            return True

    def _report(self) -> Optional[Dict[str, Any]]:
        """The report body, or None when this install can't say who it is yet."""
        key = clean(_get(self._license_key), 128)
        licensed = bool(key and self._api_key and self._fingerprint)
        if not licensed and not self._product_analytics_id:
            return None
        r: Dict[str, Any] = {"schema": 1}
        if licensed:
            r["licenseKey"] = key
            r["fingerprint"] = self._fingerprint
        if self._product_analytics_id:
            r["productAnalyticsId"] = self._product_analytics_id
            r["installId"] = self._installation_id()  # also with a license: an unknown key then still counts
        r["sdk"] = {"name": SDK_NAME, "version": SDK_VERSION}
        metrics: Dict[str, Any] = {}
        _put(metrics, "productVersion", clean(_get(self._product_version), 64))
        metrics.update(self._system_metrics())
        r["metrics"] = metrics
        for section in self._sections:
            try:
                section.write(r)
            except Exception:  # noqa: BLE001 - a broken section is left out, the built-in metrics still go
                pass
        return r

    def _system_metrics(self) -> Dict[str, Any]:
        with self._lock:
            if self._metrics is None:
                self._metrics = self._collect() if self._collect else collect(self._platform or detect_platform())
            return self._metrics

    def _installation_id(self) -> str:
        with self._lock:
            if self._install_id:
                return self._install_id
            try:
                with open(self._install_id_file, encoding="utf-8") as f:
                    stored = f.read().strip()
                if _INSTALL_ID.match(stored):
                    self._install_id = stored
                    return stored
            except (OSError, ValueError):
                pass  # missing or unreadable: make a new one
            self._install_id = str(uuid.uuid4())
            try:
                os.makedirs(os.path.dirname(self._install_id_file) or ".", exist_ok=True)
                with open(self._install_id_file, "w", encoding="utf-8") as f:
                    f.write(self._install_id)
            except OSError:
                pass  # read-only disk: this run still has an id
            return self._install_id

    def _outcome(self, kind: str, message: str) -> None:
        if kind != self._last_outcome:
            self._last_outcome = kind
            _LOG.debug("SunLicense analytics: %s", message)


_MAX_FEATURES = 50
_MAX_CHARTS = 30
_MAX_VALUES = 50
_MAX_BAR = 20
_MAX_NUMBER = 10 ** 9
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")


def chart_id(value: Any) -> Optional[str]:
    """Feature names and chart ids: lower-cased, ``[a-z0-9][a-z0-9._-]{0,47}``, else None."""
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    return key if _ID.match(key) else None


class _UsageSection:
    """Feature usage (kept until a report is stored) and custom charts (callbacks run before each report)."""

    def __init__(self, analytics: SunLicenseAnalytics) -> None:
        self._analytics = analytics
        self._sending: Optional[Dict[str, int]] = None
        self._report: Optional[Dict[str, Any]] = None

    def write(self, report: Dict[str, Any]) -> None:
        a = self._analytics
        self._report = report
        with a._lock:
            features = dict(list(a._features.items())[:_MAX_FEATURES])
            charts = list(a._charts.items())
        self._sending = features or None
        if features:
            report["features"] = features
        out = []
        for key, (kind, callback) in charts:
            if len(out) >= _MAX_CHARTS:
                break
            try:
                data = chart_data(kind, callback())
            except Exception:  # noqa: BLE001 - a callback that raises leaves its chart out
                data = None
            if data:
                out.append({"id": key, "type": kind, "data": data})
        if out:
            report["charts"] = out

    def sent(self, accepted: bool) -> None:
        sending, self._sending = self._sending, None
        if not accepted or not sending or "features" not in (self._report or {}):  # left out of a report over 16 KB
            return
        a = self._analytics
        with a._lock:
            for name, uses in sending.items():
                left = a._features.get(name, 0) - uses
                if left > 0:
                    a._features[name] = left
                else:
                    a._features.pop(name, None)


def _number(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_NUMBER:
        return value
    return None


def _numbers(value: Any, minimum: int) -> Optional[Dict[str, int]]:
    out: Dict[str, int] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            key = clean(k, 64)
            if key and _number(v) is not None and v >= minimum and len(out) < _MAX_VALUES:
                out[key] = v
    return out or None


def chart_data(kind: str, value: Any) -> Optional[Dict[str, Any]]:
    """A chart callback's value as the report's ``data``, or None when there's nothing (valid) to send."""
    if value is None:
        return None
    if kind == "simple_pie":
        v = clean(value, 64) if isinstance(value, str) else None
        return {"value": v} if v else None
    if kind == "single_line":
        return {"value": value} if _number(value) is not None else None
    if kind in ("advanced_pie", "multi_line", "simple_bar"):
        values = _numbers(value, 1 if kind == "advanced_pie" else -_MAX_NUMBER)
        return {"values": values} if values else None
    if kind == "drilldown_pie" and isinstance(value, dict):
        out: Dict[str, Any] = {}
        for outer, inner in value.items():
            key, piece = clean(outer, 64), _numbers(inner, 1)
            if key and piece and len(out) < _MAX_VALUES:
                out[key] = piece
        return {"values": out} if out else None
    if kind == "advanced_bar" and isinstance(value, dict):
        bars: Dict[str, Any] = {}
        for k, items in value.items():
            key = clean(k, 64)
            nums: List[int] = []
            for x in items if isinstance(items, (list, tuple)) else []:
                if len(nums) >= _MAX_BAR or _number(x) is None:
                    break  # up to 20 numbers, until the first that isn't one
                nums.append(x)
            if key and nums and len(bars) < _MAX_VALUES:
                bars[key] = nums
        return {"values": bars} if bars else None
    return None


def first_delay(rng: Any = None) -> float:
    """First report after a random 1-30 minutes, so a fleet restarted together doesn't report together."""
    return float(60 + (rng or _random_module()).randint(0, 29 * 60))


def next_delay(status: int, retry_after: Optional[str]) -> float:
    """30 minutes after a 204 or no answer; else the server's Retry-After, between 1 minute and 24 hours."""
    if status == 204 or retry_after is None:
        return INTERVAL
    try:
        seconds = int(str(retry_after).strip())
    except ValueError:
        return INTERVAL  # an HTTP date: not something our server sends
    return min(MAX_WAIT, max(MIN_WAIT, float(max(0, seconds))))


def is_off(value: Optional[str]) -> bool:
    return value is not None and str(value).strip().lower() in _OFF


def collect(platform: Optional[Tuple[str, Optional[str]]]) -> Dict[str, Any]:
    """Raw values; the server maps them to families and majors."""
    m: Dict[str, Any] = {}
    system = _safe(_platform.system) or ""
    if system == "Darwin":
        _put(m, "os", "Mac OS X")
        _put(m, "osVersion", clean(_safe(lambda: _platform.mac_ver()[0]), 64))
    elif system == "Windows":
        release = _safe(_platform.release) or ""
        # "10", "11", "2022Server" -> "Windows 11", "Windows Server 2022"
        server = re.match(r"^(\d{4})Server", release)
        name = "Windows Server " + server.group(1) if server else ("Windows " + release if release.isdigit() else "Windows")
        _put(m, "os", name)
        _put(m, "osVersion", clean(_safe(_platform.version), 64))
    else:
        _put(m, "os", clean(system, 64))
        _put(m, "osVersion", clean(_safe(_platform.release), 64))
    _put(m, "arch", clean(_safe(_platform.machine), 64))
    cores = _safe(os.cpu_count)
    if isinstance(cores, int) and cores > 0:
        m["cores"] = min(1024, cores)
    _put(m, "locale", clean(_locale(), 64))
    m["runtime"] = "python"
    _put(m, "runtimeVersion", clean(_safe(_platform.python_version), 64))
    if platform:
        name, version = (list(platform) + [None])[:2]
        _put(m, "platform", clean(str(name).lower() if name else None, 32))
        _put(m, "platformVersion", clean(version, 64))
    return m


def _locale() -> Optional[str]:
    try:
        value = locale.getlocale()[0]
    except (ValueError, TypeError):
        value = None
    if not value or value in ("C", "POSIX"):
        for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
            env = os.environ.get(name)
            if env and env not in ("C", "POSIX") and not env.startswith("C."):
                return env
        return None
    return value


def detect_platform() -> Tuple[str, Optional[str]]:
    """What the product runs on, from modules it has already imported: a Discord bot, else standalone."""
    try:
        for module in ("discord", "nextcord", "disnake", "interactions", "hikari"):
            loaded = sys.modules.get(module)
            if loaded is not None:
                return "discord", clean(str(getattr(loaded, "__version__", "") or ""), 64)
    except Exception:  # noqa: BLE001
        pass
    return "standalone", None


def clean(value: Any, limit: int) -> Optional[str]:
    """Trimmed, control characters removed, cut at ``limit``; None when empty."""
    if value is None:
        return None
    s = _CONTROL.sub("", str(value)).strip()
    if not s:
        return None
    if len(s) > limit:
        s = s[:limit].strip()
    return s or None


def _supplier(value: StrOrSupplier) -> Callable[[], Optional[str]]:
    return value if callable(value) else (lambda: value)


def _get(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


_safe = _get


def _put(m: Dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        m[key] = value


def _json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False, default=str).encode("utf-8")


def _random_module() -> Any:
    return random.SystemRandom()


def _http_post(url: str, headers: Dict[str, str], body: bytes) -> Tuple[int, Optional[str]]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            response.read()
            return response.status, response.headers.get("Retry-After")
    except urllib.error.HTTPError as error:
        try:
            error.read()
        except Exception:  # noqa: BLE001
            pass
        return error.code, error.headers.get("Retry-After") if error.headers else None
    except Exception:  # noqa: BLE001
        return -1, None
