# Wutong SDK for Python · 梧桐 Python SDK

[![CI](https://github.com/project-wutong/wutong-sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/project-wutong/wutong-sdk-python/actions/workflows/ci.yml)
Python ≥ 3.9 (abi3 wheel) · Rust core via PyO3 · `AGPL-3.0-only`

## 中文

Python 绑定直接调用 Rust 实现的 [`wutong-core`](https://github.com/project-wutong/wutong-core)，协议规则只实现一次。
提供：严格 JSON + JCS 规范化、dCBOR、`sha256:` 摘要、信封完整校验（JSON Schema + 语义）、Ed25519 签名与验签。
错误以 `wutong.WtpException(code, detail)` 抛出，`code` 为规范错误码（如 `ERR_SCHEMA`）。

```bash
pip install maturin && maturin develop   # 本地开发
```

```python
import wutong
wutong.validate(raw)                     # -> "wutong.principal"
signed = wutong.sign(raw, seed, signer_id, key_id, issued_at, nonce)
wutong.verify(signed.encode(), public_key_hex)
```

## English

PyO3 bindings over the Rust core. Tests run the full 24-kind cross-language signature vectors
from `wutong-protocol` and require byte-identical output. (The reference Python implementation
that ships with the protocol package stays in `wutong-protocol` as an independent conformance
oracle; this SDK is the supported library.)
