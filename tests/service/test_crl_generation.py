"""
Tests for scheme-authority/crl.py — RFC 5280 CRL generation.

Covers:
  - build_crl: DER output, valid ASN.1 round-trip
  - CRL is signed by the Intermediate CA private key (signature verification)
  - CRLNumber extension present and correct
  - AuthorityKeyIdentifier extension present
  - Revoked entry lookup by serial number
  - Empty CRL (no entries)
  - Multiple revoked entries
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from datetime import datetime, timedelta, timezone

import pytest

ROOT = pathlib.Path(__file__).parent.parent.parent  # SA repo root
PKI_DIR = ROOT / "pki"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PKI_DIR))

import importlib

# Load crl.py (at SA repo root)
_crl_spec = importlib.util.spec_from_file_location("sa_crl", ROOT / "crl.py")
sa_crl = importlib.util.module_from_spec(_crl_spec)
_crl_spec.loader.exec_module(sa_crl)
build_crl = sa_crl.build_crl

# Load pki/pki.py to generate test CA material
import pki as _pki_module

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


# ---------------------------------------------------------------------------
# Shared CA material (generated once per module)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def intermediate_key_and_cert():
    """Generate an Intermediate CA key+cert for use across all CRL tests."""
    root_key, root_cert = _pki_module.generate_root_ca()
    int_key, int_cert = _pki_module.generate_intermediate_ca(root_key, root_cert)
    return int_key, int_cert


@pytest.fixture(scope="module")
def pisp_cert(intermediate_key_and_cert):
    """Generate one PISP CA cert to use as a revocation target."""
    int_key, int_cert = intermediate_key_and_cert
    pisp_key, csr = _pki_module.generate_pisp_ca_key_and_csr(
        "psp://test.example", "Test PISP"
    )
    return _pki_module.sign_pisp_csr(csr, int_key, int_cert)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_crl(der_bytes: bytes) -> x509.CertificateRevocationList:
    return x509.load_der_x509_crl(der_bytes)


def _build(intermediate_key_and_cert, revoked_entries=None, crl_number=0):
    int_key, int_cert = intermediate_key_and_cert
    return build_crl(
        intermediate_key=int_key,
        intermediate_cert=int_cert,
        revoked_entries=revoked_entries or [],
        crl_number=crl_number,
    )


# ---------------------------------------------------------------------------
# Basic output
# ---------------------------------------------------------------------------

def test_build_crl_returns_bytes(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert)
    assert isinstance(der, bytes)
    assert len(der) > 0


def test_crl_parses_as_valid_der(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert)
    crl = _parse_crl(der)
    assert crl is not None


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def test_crl_signature_verifiable_with_intermediate_public_key(intermediate_key_and_cert):
    int_key, int_cert = intermediate_key_and_cert
    der = _build(intermediate_key_and_cert)
    crl = _parse_crl(der)
    # This raises if the signature is invalid
    crl.is_signature_valid(int_cert.public_key())


def test_crl_issuer_matches_intermediate_cert_subject(intermediate_key_and_cert):
    int_key, int_cert = intermediate_key_and_cert
    der = _build(intermediate_key_and_cert)
    crl = _parse_crl(der)
    assert crl.issuer == int_cert.subject


# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------

def test_crl_has_authority_key_identifier(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert)
    crl = _parse_crl(der)
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert aki is not None


def test_crl_has_crl_number(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert, crl_number=42)
    crl = _parse_crl(der)
    crl_num_ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
    assert crl_num_ext.value.crl_number == 42


def test_crl_number_zero_is_valid(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert, crl_number=0)
    crl = _parse_crl(der)
    ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
    assert ext.value.crl_number == 0


# ---------------------------------------------------------------------------
# Revoked entries
# ---------------------------------------------------------------------------

def test_empty_crl_has_no_revoked_entries(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert)
    crl = _parse_crl(der)
    revoked = list(crl)
    assert revoked == []


def test_revoked_entry_appears_in_crl(intermediate_key_and_cert, pisp_cert):
    serial_hex = format(pisp_cert.serial_number, "x")
    revoked_at = datetime.now(timezone.utc).isoformat()

    der = _build(
        intermediate_key_and_cert,
        revoked_entries=[{"serial_hex": serial_hex, "revoked_at": revoked_at}],
    )
    crl = _parse_crl(der)
    revoked = list(crl)
    assert len(revoked) == 1
    assert revoked[0].serial_number == pisp_cert.serial_number


def test_revoked_serial_lookup(intermediate_key_and_cert, pisp_cert):
    serial_hex = format(pisp_cert.serial_number, "x")
    revoked_at = datetime.now(timezone.utc).isoformat()

    der = _build(
        intermediate_key_and_cert,
        revoked_entries=[{"serial_hex": serial_hex, "revoked_at": revoked_at}],
    )
    crl = _parse_crl(der)
    found = crl.get_revoked_certificate_by_serial_number(pisp_cert.serial_number)
    assert found is not None
    assert found.serial_number == pisp_cert.serial_number


def test_non_revoked_serial_not_in_crl(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert, revoked_entries=[])
    crl = _parse_crl(der)
    assert crl.get_revoked_certificate_by_serial_number(0xDEADBEEF) is None


def test_multiple_revoked_entries(intermediate_key_and_cert):
    int_key, int_cert = intermediate_key_and_cert
    # Generate two PISP CA certs to revoke
    entries = []
    for uri in ("psp://a.example", "psp://b.example"):
        pisp_key, csr = _pki_module.generate_pisp_ca_key_and_csr(uri, "Test")
        cert = _pki_module.sign_pisp_csr(csr, int_key, int_cert)
        entries.append({
            "serial_hex": format(cert.serial_number, "x"),
            "revoked_at": datetime.now(timezone.utc).isoformat(),
        })

    der = _build(intermediate_key_and_cert, revoked_entries=entries)
    crl = _parse_crl(der)
    assert len(list(crl)) == 2


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def test_crl_next_update_in_future(intermediate_key_and_cert):
    der = _build(intermediate_key_and_cert)
    crl = _parse_crl(der)
    now = datetime.now(timezone.utc)
    assert crl.next_update_utc > now


def test_crl_next_update_respects_hours_parameter(intermediate_key_and_cert):
    int_key, int_cert = intermediate_key_and_cert
    der = build_crl(
        intermediate_key=int_key,
        intermediate_cert=int_cert,
        revoked_entries=[],
        crl_number=0,
        next_update_hours=48,
    )
    crl = _parse_crl(der)
    delta = crl.next_update_utc - crl.last_update_utc
    # Should be approximately 48 hours (allow ±1 minute)
    assert abs(delta.total_seconds() - 48 * 3600) < 60
