# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-language vectors from wutong-protocol: the Python SDK must be byte-exact."""
import json
import pathlib

import pytest

import wutong

V = pathlib.Path(__file__).parent / "vectors"
SIG = json.loads((V / "signatures.json").read_text(encoding="utf-8"))
SEED = bytes.fromhex(SIG["seed_hex"])
PUB = wutong.public_key_hex(SEED)


def raw(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode()


@pytest.mark.parametrize("case", SIG["cases"], ids=lambda c: c["name"])
def test_examples(case):
    ex = raw(case["example"])
    assert wutong.canonicalize(ex) == case["jcs_unsigned_example"]
    assert wutong.digest(case["jcs_unsigned_example"].encode()) == case["jcs_sha256"]
    assert wutong.to_dcbor(ex).hex() == case["dcbor_hex_example"]
    if case["name"] == "sync_frame":
        # Known spec/example conflict: the HELLO example omits supported_codecs, which the
        # semantic rules require (tracked as a needs-decision issue in wutong-protocol).
        with pytest.raises(wutong.WtpException):
            wutong.validate(ex)
    else:
        assert wutong.validate(ex) == case["kind"]
    signed = wutong.sign(ex, SEED, SIG["signer_id"], SIG["key_id"], SIG["issued_at"], SIG["nonce"])
    assert signed == wutong.canonicalize(raw(case["signed_jcs"]))
    wutong.verify(signed.encode(), PUB)


def test_tamper_rejected():
    case = SIG["cases"][0]
    env = dict(case["signed_jcs"], occurred_at="2026-10-18T10:00:01Z")
    with pytest.raises(wutong.WtpException) as e:
        wutong.verify(raw(env), PUB)
    assert e.value.args[0] == "ERR_SIGNATURE"


@pytest.mark.parametrize("hexcase", json.loads((V / "strict_json_negative.json").read_text()))
def test_strict_negative(hexcase):
    with pytest.raises(wutong.WtpException) as e:
        wutong.canonicalize(bytes.fromhex(hexcase["hex"]))
    assert e.value.args[0] == "ERR_SCHEMA"


def test_meta():
    assert wutong.PROTOCOL == "wutong/0.1"
    assert wutong.IMPLEMENTATION.startswith("wutong-core-rs/")
