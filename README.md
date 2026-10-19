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

- **0.0.2**: send a `sunlicense-python/<version>` User-Agent. 0.0.1 sent urllib's default
  (`Python-urllib/3.x`), which Cloudflare in front of `api.sunlicense.com` refuses with
  `403` and the text body `error code: 1010`, so every validation failed. A body that isn't JSON
  is now returned as text in `data` instead of `None`.
- **0.0.1**: first release.

## Requirements

Python 3.8 or newer.

## Other clients

SunLicense also provides clients for **Java**, **JavaScript**, **PHP** and **Lua**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-py/issues

## Licence

MIT © Hapangama
