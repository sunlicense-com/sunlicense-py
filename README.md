# SunLicense — Python Client

Official Python client for [SunLicense](https://sunlicense.com), a licence management and
anti-piracy system for indie software developers.

SunLicense issues, validates and revokes licence keys for Minecraft plugins, Discord bots,
FiveM scripts, desktop apps and other paid software — with marketplace automation for
BuiltByBit and Polymart.

> **Early release.** Licence validation works today. The wider client surface — activations,
> entitlements and offline verification — is in active development.

## Install

```bash
pip install sunlicense
```

No dependencies — standard library only.

## Usage

```python
from sunlicense import SunLicense

client = SunLicense(
    base_url="https://your-instance.example.com",
    token="optional-api-token",
)

result = client.validate("LICENCE-KEY-HERE")

if result.valid:
    print("Licence is valid")
else:
    print("Rejected:", result.status, result.data)
```

Pass extra context as keyword arguments:

```python
result = client.validate("LICENCE-KEY-HERE", product="my-plugin", host="server-01")
```

### `SunLicense(...)`

| Argument | Type | Default | Description |
|---|---|---|---|
| `base_url` | `str` | — | **Required.** Base URL of your SunLicense instance |
| `token` | `str` | `None` | API token, if your endpoint requires one |
| `timeout` | `float` | `10.0` | Request timeout in seconds |

### `validate(license_key, **context) -> ValidationResult`

Returns a named tuple with `valid` (`bool`), `status` (`int`) and `data` (the parsed JSON body,
the body as text when it isn't JSON, or `None` when it's empty).

Requests carry the header `User-Agent: sunlicense-python/<version>`.

## Changelog

- **0.2.0**: core unlock, tamper reports, the ownership notice and protected files: `client.protection()`, `SunLicenseProtection`.
- **0.1.0**: built-in product analytics (opt-out), feature usage and custom charts: `client.analytics()`, `SunLicense.analytics_for()`.
- **0.0.2**: send a `sunlicense-python/<version>` User-Agent. 0.0.1 sent urllib's default
  (`Python-urllib/3.x`), which Cloudflare in front of `api.sunlicense.com` refuses with
  `403` and the text body `error code: 1010`, so every validation failed. A body that isn't JSON
  is now returned as text in `data` instead of `None`.
- **0.0.1**: first release.

## Built-in analytics

Reports anonymous usage statistics for your product's **Analytics** tab (installs, versions, OS, Python,
platform), plus your own feature usage and charts. Like bStats, for every product.

```python
from sunlicense import SunLicense

# A licensed product: the API key, license key and machine id it validates with.
analytics = client.analytics(license_key, machine_id, product_version="2.3.1",
                             enabled=config.get("analytics", True))
# A free product, no license: its public product analytics id (Product -> Analytics).
analytics = SunLicense.analytics_for("pa_7Hk2mQ9xZr4LbN8vT1wYcD", data_directory="data")

analytics.feature("auto-sell")                                # feature usage
analytics.simple_pie("storage", lambda: config["storage"])    # custom charts
analytics.single_line("servers", lambda: len(bot.guilds))
analytics.close()                                             # on shutdown
```

Charts: `simple_pie`, `advanced_pie`, `drilldown_pie`, `single_line`, `multi_line`, `simple_bar`,
`advanced_bar`, `remove_chart`. Ids and feature names: `[a-z0-9][a-z0-9._-]{0,47}`. Callbacks run on the
analytics thread (a daemon thread) before each report; one that raises or returns nothing is left out.

**What is sent** (raw values; SunLicense groups them, e.g. `5.15.0-1051-oracle` into Linux 5.15): your
product version, the OS and its version, CPU architecture, CPU cores, locale, Python version, the platform (`discord` when discord.py, nextcord, disnake, interactions.py or hikari is imported, with its version, else `standalone`),
the SDK's name and version, and the identity: licensed = license key + machine id (with the API key), free =
the product analytics id + a random install id kept in `.sunlicense-install-id` in `data_directory` (default `~/.sunlicense`). The country comes from SunLicense's edge, not
from the SDK. Nothing personal is sent: no user, host, server or player names, IP addresses or file paths.

**Switching it off.** Nothing is sent, not even an empty report, while any of these says so (checked before
every report): your product's own switch (`enabled=False`, or a callable read before each report); the environment variable `SUNLICENSE_ANALYTICS=off` (also
`false` or `0`).

The first report goes 1 to 30 minutes after start (random), then one every 30 minutes. When
SunLicense answers with `Retry-After` (analytics switched off for the product, rate limits) it waits that long,
at most 24 hours. Reporting never runs on the license check's path, never delays or fails a check, and swallows
its own errors.

Docs: https://docs.sunlicense.com/guide/sdks#built-in-analytics

## Protection: core unlock, tamper reports, ownership notice

`sunlicense seal <file> --product <code> [--digest <files>]` (the [CLI](https://docs.sunlicense.com/cli/)) encrypts
part of your product, its *core*, on SunLicense's servers under a key only they hold, and prints the sealed text
(`SLS1.…`) you ship. A valid license check answers with that key (`unlock`); a refused one (suspended, expired,
revoked) doesn't, and this SDK forgets the one it had. So a copy whose license check was cut out can't run its core.
The unlock from the last valid check is cached for 7 days (in `cache_directory`, default `~/.sunlicense`), encrypted under a key bound to the license key,
the machine id and this machine, so outages don't stop your customers.

```python
client = SunLicense(base_url="https://api.sunlicense.com", token=os.environ["SUNLICENSE_API_KEY"])
protection = client.protection(license_key=key, fingerprint=machine_id, product="My Bot",
                               owner="Example Studio", terms="https://example.com/terms", cache_directory="data")
print(protection.notice())                    # product, owner, masked key
client.validate(key, fingerprint=machine_id)  # sends integrity, keeps or forgets the unlock
core = protection.unseal(SEALED_CORE)         # bytes; raises Locked without a valid unlock
protection.integrity(os.path.dirname(__file__))  # "OK" / "MODIFIED", sent with the next check
```

- `unseal(sealed)`: the core, or raises `Locked` without a valid unlock (or for data sealed for another product).
- `integrity(...)`: compares the files whose digests were sealed with the core (`--digest`) with what is running;
  `OK` or `MODIFIED` (with the changed files) is sent with the next check, where Sentinel sees it.
- `notice()`: `My Bot is licensed software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: …`; never the full
  key or the buyer's name.
- `protection.protected_file(name)`: a file uploaded to the product (Standard plan), sent only while the license is valid.
- `accept(body)` and `protection.validate_fields()`: for your own HTTP code; the client does both when you create the protection from it.
- `accept_offline(file, public_key)`: the unlock from a valid [offline license file](https://docs.sunlicense.com/guide/offline-licenses) (needs `cryptography`).
- Still no dependencies: AES-GCM uses `cryptography` when it's installed and a pure-Python implementation otherwise.

Honest limit: someone with a valid license can still extract the unlock and patch their copy; that copy then fails
its integrity check and is reported. Protection raises the cost and makes leaks visible. Wire format and test
vectors: `tests/fixtures/protection-test-vectors.json` (a copy of SunLicense's); docs:
https://docs.sunlicense.com/guide/protection

## Requirements

Python 3.8 or newer.

## Other clients

SunLicense also provides clients for **Java**, **JavaScript**, **PHP** and **Lua**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-py/issues

## Tests

```bash
python -m unittest discover -s tests
```

## Licence

MIT © Hapangama
