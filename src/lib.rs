// SPDX-License-Identifier: AGPL-3.0-only
//! PyO3 bindings. All protocol logic lives in `wutong-core`; this crate only converts types.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use wutong_core::crypto::{self, Encoding, Mode, SignParams, VerifyOptions};
use wutong_core::types::WtpError;
use wutong_core::wire::{dcbor, jcs, sha256_digest, strict};

create_exception!(
    _native,
    WtpException,
    PyException,
    "A Wutong Protocol error; args = (code, detail)."
);

fn py_err(e: WtpError) -> PyErr {
    WtpException::new_err((e.code.as_str().to_string(), e.detail.clone()))
}

fn enc(name: &str) -> PyResult<Encoding> {
    match name {
        "jcs" => Ok(Encoding::Jcs),
        "dcbor" => Ok(Encoding::Dcbor),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "encoding must be 'jcs' or 'dcbor'",
        )),
    }
}

/// Strictly parse JSON bytes and return the RFC 8785 canonical form (str).
#[pyfunction]
fn canonicalize(data: &[u8]) -> PyResult<String> {
    let v = strict::parse(data).map_err(py_err)?;
    let out = jcs::canonicalize(&v).map_err(py_err)?;
    Ok(String::from_utf8(out).expect("JCS output is UTF-8"))
}

/// Strictly parse JSON bytes and return their deterministic CBOR encoding.
#[pyfunction]
fn to_dcbor(data: &[u8]) -> PyResult<Vec<u8>> {
    let v = strict::parse(data).map_err(py_err)?;
    dcbor::encode(&v).map_err(py_err)
}

/// `sha256:<hex>` of the exact bytes.
#[pyfunction]
fn digest(data: &[u8]) -> String {
    sha256_digest(data).to_string()
}

/// Strict parse + JSON Schema + semantic validation. Returns the message kind.
#[pyfunction]
fn validate(data: &[u8]) -> PyResult<String> {
    let env = wutong_core::parse_and_validate(data).map_err(py_err)?;
    Ok(env.kind().as_str().to_string())
}

/// Sign an unsigned envelope with a 32-byte Ed25519 seed; returns signed JCS JSON.
#[pyfunction]
#[pyo3(signature = (data, seed, signer_id, key_id, issued_at, nonce, encoding="jcs"))]
#[allow(clippy::too_many_arguments)]
fn sign(
    data: &[u8],
    seed: &[u8],
    signer_id: &str,
    key_id: &str,
    issued_at: &str,
    nonce: &str,
    encoding: &str,
) -> PyResult<String> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("seed must be 32 bytes"))?;
    let e = enc(encoding)?;
    let v = strict::parse(data).map_err(py_err)?;
    let key = crypto::signing_key_from_seed(&seed);
    let p = SignParams {
        signer_id,
        key_id,
        issued_at,
        nonce,
        encoding: e,
        include_encoding: e == Encoding::Dcbor,
    };
    let signed = crypto::sign_envelope(&v, &key, &p).map_err(py_err)?;
    let out = jcs::canonicalize(&signed).map_err(py_err)?;
    Ok(String::from_utf8(out).expect("JCS output is UTF-8"))
}

/// Verify a signed JSON envelope (archive mode) against a hex public key; returns its digest.
#[pyfunction]
fn verify(data: &[u8], public_key_hex: &str) -> PyResult<String> {
    let pk = crypto::validate_public_key_hex(public_key_hex).map_err(py_err)?;
    let vk = crypto::verifying_key(&pk).map_err(py_err)?;
    let lookup = move |_: &str, _: &str| Some(vk);
    let v = strict::parse(data).map_err(py_err)?;
    let opts = VerifyOptions {
        mode: Mode::Archive,
        ..Default::default()
    };
    crypto::verify_envelope(&v, &lookup, opts).map_err(py_err)
}

/// Public key (hex) for a 32-byte seed.
#[pyfunction]
fn public_key_hex(seed: &[u8]) -> PyResult<String> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("seed must be 32 bytes"))?;
    Ok(hex::encode(
        crypto::signing_key_from_seed(&seed)
            .verifying_key()
            .to_bytes(),
    ))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("IMPLEMENTATION", wutong_core::IMPLEMENTATION)?;
    m.add("PROTOCOL", wutong_core::types::PROTOCOL)?;
    m.add("WtpException", m.py().get_type::<WtpException>())?;
    for f in [
        wrap_pyfunction!(canonicalize, m)?,
        wrap_pyfunction!(to_dcbor, m)?,
        wrap_pyfunction!(digest, m)?,
        wrap_pyfunction!(validate, m)?,
        wrap_pyfunction!(sign, m)?,
        wrap_pyfunction!(verify, m)?,
        wrap_pyfunction!(public_key_hex, m)?,
    ] {
        m.add_function(f)?;
    }
    Ok(())
}
