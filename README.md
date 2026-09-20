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

Returns a named tuple with `valid` (`bool`), `status` (`int`) and `data` (parsed JSON or
`None`).

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
