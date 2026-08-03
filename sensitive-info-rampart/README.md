# `arcjet-sensitive-info-rampart`

[Arcjet][arcjet] helps developers protect their apps in just a few lines of
code. Implement rate limiting, bot protection, email verification, and defense
against common attacks.

This package is an alternative **detection backend** for Arcjet's
[sensitive information][sensitive-info] rule. It runs the on-device
[Rampart][rampart] named-entity-recognition model — a ~15&nbsp;MB quantized ONNX
model — so the rule can detect names, addresses, and government/financial
identifiers in addition to the four types the default WebAssembly engine
detects. Everything runs locally; no data leaves your environment, and the model
weights are bundled so nothing is fetched at runtime.

## Installation

Install Arcjet with the `sensitive-info-rampart` extra, which pulls in this
package and its runtime dependencies (`onnxruntime`, `tokenizers`, `numpy`):

```shell
pip install "arcjet[sensitive-info-rampart]"
```

## Usage

Pass the backend to the `detect_sensitive_info` rule via its `backend` option.
The rest of the rule — `mode`, `allow`/`deny`, and the result shape — is
unchanged.

```python
import os

from arcjet import arcjet, detect_sensitive_info, Mode
from arcjet_sensitive_info_rampart import rampart

aj = arcjet(
    key=os.environ["ARCJET_KEY"],
    rules=[
        detect_sensitive_info(
            mode=Mode.LIVE,
            # Every Rampart entity is a built-in type.
            deny=["EMAIL", "GIVEN_NAME", "SURNAME", "STREET_NAME", "SSN"],
            backend=rampart(),
        ),
    ],
)

decision = await aj.protect(
    request,
    sensitive_info_value="My name is Alex Rivera and my SSN is 472-81-0094.",
)
```

It also works with `arcjet.guard`:

```python
from arcjet.guard import LocalDetectSensitiveInfo
from arcjet_sensitive_info_rampart import rampart

sensitive = LocalDetectSensitiveInfo(deny=["GIVEN_NAME", "SSN"], backend=rampart())
```

Without a `backend`, the rule continues to use the default WebAssembly engine —
this package is entirely opt-in.

## Detected entities

The model detects: `GIVEN_NAME`, `SURNAME`, `EMAIL`, `PHONE_NUMBER`, `URL`,
`TAX_ID`, `BANK_ACCOUNT`, `ROUTING_NUMBER`, `GOVERNMENT_ID`, `PASSPORT`,
`DRIVERS_LICENSE`, `BUILDING_NUMBER`, `STREET_NAME`, `SECONDARY_ADDRESS`,
`CITY`, `STATE`, and `ZIP_CODE`.

Deterministic recognizers additionally detect the structured, validatable types
`EMAIL`, `URL`, `IP_ADDRESS`, `SSN`, and `CREDIT_CARD_NUMBER` (Luhn-validated),
mirroring Rampart's deterministic redaction layer. Phone numbers are left to
the model because their digit shape overlaps with financial and government
identifiers. On overlapping text the recognizer result wins over the model.

The full set is exported as `rampart_entities`:

```python
from arcjet_sensitive_info_rampart import rampart, rampart_entities

detect_sensitive_info(deny=list(rampart_entities), backend=rampart())
```

## Options

```python
from arcjet_sensitive_info_rampart import RampartOptions, default_recognizers, rampart

rampart(
    RampartOptions(
        # Minimum confidence for a model token to count (default: 0.5).
        threshold=0.6,
        # ONNX Runtime execution providers (default: ("CPUExecutionProvider",)).
        providers=("CPUExecutionProvider",),
        # Add or replace the deterministic recognizers. This is the extension
        # point for custom detection with this backend.
        recognizers=(*default_recognizers, my_recognizer),
        # Max characters scanned per request (default: DEFAULT_MAX_INPUT_CHARS,
        # i.e. 100_000). Longer input is truncated before detection and a
        # warning is logged. See "Limiting input size" below.
        max_input_chars=100_000,
    )
)
```

The model loads once on first use and is reused for every request. The
token-based `detect` callback of the `detect_sensitive_info` rule is not used by
this backend; add a recognizer instead.

### Limiting input size

Inference is synchronous and its cost grows with the input length, so an
unbounded value is a denial-of-service vector. By default the backend scans at
most `DEFAULT_MAX_INPUT_CHARS` (100,000) characters per request; longer input is
truncated to that prefix before detection and a warning is logged. Raise the
limit to scan larger payloads (at the cost of latency), or lower it to tighten
the per-request bound:

```python
from arcjet_sensitive_info_rampart import (
    DEFAULT_MAX_INPUT_CHARS,
    RampartOptions,
    rampart,
)

# Scan up to 500k characters instead of the default 100k.
backend = rampart(RampartOptions(max_input_chars=500_000))

# Or tighten it for a latency-sensitive path.
strict = rampart(RampartOptions(max_input_chars=10_000))

print(DEFAULT_MAX_INPUT_CHARS)  # 100000
```

> [!NOTE]
> Inference runs synchronously in the request path, so its latency affects
> request handling. The model performs best on Latin-script text; see the
> [model card][rampart] for accuracy and language details.

## License

The source code of this package is licensed under the
[Apache License, Version 2.0][apache-license] © [Arcjet Labs, Inc.][arcjet]

### Bundled model

This package bundles the [Rampart][rampart] model and its tokenizer/configuration
files (under `src/arcjet_sensitive_info_rampart/models/rampart/`), which are a
separate work:

> "Rampart: Client-side PII redaction for AI assistants" by
> [National Design Studio][rampart], Copyright 2026 National Design Studio,
> licensed under [CC BY 4.0][cc-by-4]. The files are redistributed unmodified.

The full model license is in
[`models/rampart/LICENSE`](./src/arcjet_sensitive_info_rampart/models/rampart/LICENSE)
and the attribution is recorded in [`NOTICE`](./NOTICE). If you redistribute this
package or the model files, retain that attribution as required by CC BY 4.0.

[arcjet]: https://arcjet.com
[sensitive-info]: https://docs.arcjet.com/sensitive-info
[rampart]: https://huggingface.co/nationaldesignstudio/rampart
[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
[cc-by-4]: https://creativecommons.org/licenses/by/4.0/
