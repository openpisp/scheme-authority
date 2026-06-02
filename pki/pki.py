"""
PSP Scheme PKI library.

Provides all certificate generation and validation primitives used by:
  - pki/ scripts  (scheme CA setup, PISP onboarding, leaf cert issuance)
  - tests/pki/    (unit and integration tests for the PKI workflow)
  - pisp/         (signing and verification of Protocol B messages — future)

The hierarchy this library implements:

  Scheme Root CA          (pathLen=2, self-signed)
      └── Scheme Intermediate CA  (pathLen=1, signed by Root)
              └── PISP CA         (pathLen=0, signed by Intermediate — one per PISP)
                      └── PISP leaf cert  (end-entity, signed by PISP CA)

All keys are EC P-256 (used with ES256 / ECDSA-SHA256 for JWS signing).
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEME_NAME = "PSP Scheme"
KEY_ALGORITHM = ec.SECP256R1()          # P-256 — matches ES256
HASH_ALGORITHM = hashes.SHA256()

# Suggested lifetimes (can be overridden by callers)
ROOT_CA_LIFETIME_DAYS    = 365 * 10     # 10 years — offline, rarely rotated
INTERMEDIATE_LIFETIME_DAYS = 365 * 5   # 5 years
PISP_CA_LIFETIME_DAYS    = 365 * 3     # 3 years — revocable by Scheme Operator
LEAF_LIFETIME_DAYS       = 1           # 24 hours — short-lived, PISP-autonomous


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate a new EC P-256 private key."""
    from cryptography.hazmat.backends import default_backend
    return ec.generate_private_key(KEY_ALGORITHM, default_backend())


# ---------------------------------------------------------------------------
# Certificate builder helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _not_before_after(lifetime_days: int):
    now = _utcnow()
    return now, now + datetime.timedelta(days=lifetime_days)


def _basic_constraints(is_ca: bool, path_len: Optional[int]) -> x509.BasicConstraints:
    return x509.BasicConstraints(ca=is_ca, path_length=path_len)


# ---------------------------------------------------------------------------
# Scheme Root CA
# ---------------------------------------------------------------------------

def generate_root_ca(
    lifetime_days: int = ROOT_CA_LIFETIME_DAYS,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Generate the Scheme Root CA key pair and self-signed certificate.

    pathLen=2 allows: Root → Intermediate → PISP CA → leaf.
    """
    key = generate_ec_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, SCHEME_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{SCHEME_NAME} Root CA"),
    ])
    not_before, not_after = _not_before_after(lifetime_days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(_basic_constraints(is_ca=True, path_len=2), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, HASH_ALGORITHM)
    )
    return key, cert


# ---------------------------------------------------------------------------
# Scheme Intermediate CA
# ---------------------------------------------------------------------------

def generate_intermediate_ca(
    root_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
    lifetime_days: int = INTERMEDIATE_LIFETIME_DAYS,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Generate the Scheme Intermediate CA key pair and certificate.

    Signed by the Root CA.  pathLen=1 allows: Intermediate → PISP CA → leaf.
    """
    key = generate_ec_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, SCHEME_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{SCHEME_NAME} Intermediate CA"),
    ])
    not_before, not_after = _not_before_after(lifetime_days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(_basic_constraints(is_ca=True, path_len=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, HASH_ALGORITHM)
    )
    return key, cert


# ---------------------------------------------------------------------------
# PISP CA (sub-CA issued to PISP at onboarding)
# ---------------------------------------------------------------------------

def generate_pisp_csr_from_key(
    key: ec.EllipticCurvePrivateKey,
    pisp_uri: str,
    pisp_name: str,
) -> x509.CertificateSigningRequest:
    """
    Build a PISP CA CSR from an existing private key.

    Called by the PISP at first boot when it needs to register with the Scheme
    Authority but already has a pre-generated key (from ``setup_dev_pki.py``).
    The private key never leaves the PISP host.

    The pisp_uri is embedded as a URI SAN — this binds the key to the
    PISP's registered scheme identity.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, pisp_name),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{pisp_name} CA"),
    ])
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(pisp_uri),
            ]),
            critical=False,
        )
        .sign(key, HASH_ALGORITHM)
    )


def generate_pisp_ca_key_and_csr(
    pisp_uri: str,
    pisp_name: str,
) -> tuple[ec.EllipticCurvePrivateKey, x509.CertificateSigningRequest]:
    """
    Generate a PISP CA key pair and CSR.

    Convenience wrapper for ``generate_pisp_csr_from_key`` that also generates
    a fresh key.  Used by ``setup_dev_pki.py`` and tests.

    The private key stays with the PISP; the CSR is submitted to the Scheme
    Operator for signing.
    """
    key = generate_ec_key()
    return key, generate_pisp_csr_from_key(key, pisp_uri, pisp_name)


def sign_pisp_csr(
    csr: x509.CertificateSigningRequest,
    intermediate_key: ec.EllipticCurvePrivateKey,
    intermediate_cert: x509.Certificate,
    lifetime_days: int = PISP_CA_LIFETIME_DAYS,
) -> x509.Certificate:
    """
    Sign a PISP's CSR with the Scheme Intermediate CA.

    Called by the Scheme Operator during PISP onboarding.

    pathLen=0: the PISP CA can only issue leaf certificates, not further CAs.
    This prevents a PISP from delegating signing authority to third parties.
    """
    not_before, not_after = _not_before_after(lifetime_days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(intermediate_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(_basic_constraints(is_ca=True, path_len=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_key.public_key()
            ),
            critical=False,
        )
        # Preserve the SAN from the CSR (carries the pisp_uri)
        .add_extension(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            critical=False,
        )
        .sign(intermediate_key, HASH_ALGORITHM)
    )
    return cert


# ---------------------------------------------------------------------------
# PISP leaf certificate (self-issued by PISP, short-lived)
# ---------------------------------------------------------------------------

def issue_leaf_cert(
    pisp_ca_key: ec.EllipticCurvePrivateKey,
    pisp_ca_cert: x509.Certificate,
    kid: str,
    lifetime_days: int = LEAF_LIFETIME_DAYS,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Issue a short-lived leaf certificate from the PISP CA.

    Called autonomously by the PISP — no Scheme Operator involvement.

    The kid is embedded in the CN so receivers can match it to the
    .well-known/psp-certs.json entry.  The pisp_uri SAN is inherited
    from the PISP CA's own SAN.
    """
    leaf_key = generate_ec_key()

    # Inherit the pisp_uri SAN from the issuing PISP CA
    try:
        pisp_uri_san = pisp_ca_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        pisp_uri_san = x509.SubjectAlternativeName([])

    # Extract the PISP name from the CA cert subject
    try:
        pisp_org = pisp_ca_cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )[0].value
    except (IndexError, Exception):
        pisp_org = "Unknown PISP"

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, pisp_org),
        x509.NameAttribute(NameOID.COMMON_NAME, kid),
    ])
    not_before, not_after = _not_before_after(lifetime_days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(pisp_ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(_basic_constraints(is_ca=False, path_len=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                pisp_ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(pisp_uri_san, critical=False)
        .sign(pisp_ca_key, HASH_ALGORITHM)
    )
    return leaf_key, cert


# ---------------------------------------------------------------------------
# App leaf certificate (issued by PISP CA — Protocol C payer-app auth)
# ---------------------------------------------------------------------------

def issue_app_cert_for_public_key(
    pisp_ca_key: ec.EllipticCurvePrivateKey,
    pisp_ca_cert: x509.Certificate,
    public_key: ec.EllipticCurvePublicKey,
    app_uri: str,
    kid: str,
    lifetime_days: int = 365,
) -> x509.Certificate:
    """
    Issue a payer-app credential signed by the PISP CA for a caller-supplied public key.

    The caller (payer-app) generates its own EC key pair and registers only the
    public key with the PISP.  The PISP never sees the private key.

    Returns only the signed certificate (the caller already holds the private key).
    """
    try:
        pisp_org = pisp_ca_cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )[0].value
    except (IndexError, Exception):
        pisp_org = "Unknown PISP"

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, pisp_org),
        x509.NameAttribute(NameOID.COMMON_NAME, kid),
    ])
    not_before, not_after = _not_before_after(lifetime_days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(pisp_ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(_basic_constraints(is_ca=False, path_len=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                pisp_ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(app_uri),
            ]),
            critical=False,
        )
        .sign(pisp_ca_key, HASH_ALGORITHM)
    )
    return cert


def issue_app_cert(
    pisp_ca_key: ec.EllipticCurvePrivateKey,
    pisp_ca_cert: x509.Certificate,
    app_uri: str,
    kid: str,
    lifetime_days: int = 365,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Issue a payer-app credential signed by the PISP CA.

    Like issue_leaf_cert but:
    - SAN is explicitly set to app_uri (not inherited from the PISP CA)
    - Longer default lifetime (app creds don't rotate daily like PISP leaf certs)
    - No CODE_SIGNING extended key usage — just digital_signature

    .. deprecated::
        Prefer ``issue_app_cert_for_public_key`` — the payer-app should
        generate its own key pair and register only the public key with the PISP.
    """
    app_key = generate_ec_key()
    cert = issue_app_cert_for_public_key(
        pisp_ca_key, pisp_ca_cert, app_key.public_key(), app_uri, kid, lifetime_days
    )
    return app_key, cert


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------

def validate_chain(
    leaf_cert: x509.Certificate,
    pisp_ca_cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
) -> None:
    """
    Validate the full certificate chain: leaf → PISP CA → Intermediate → Root.

    Checks:
      - Each certificate is signed by the next in the chain
      - pathLen constraints are respected
      - All certificates are within their validity period
      - PISP CA has pathLen=0
      - Leaf cert is not a CA

    Raises ValueError with a descriptive message on any failure.
    This is the core chain validation that receivers perform on every
    inbound Protocol B message (after fetching certs from .well-known).
    """
    now = _utcnow()

    # -- Validity periods --
    for name, cert in [
        ("Root CA", root_cert),
        ("Intermediate CA", intermediate_cert),
        ("PISP CA", pisp_ca_cert),
        ("Leaf", leaf_cert),
    ]:
        if now < cert.not_valid_before_utc:
            raise ValueError(f"{name} certificate is not yet valid")
        if now > cert.not_valid_after_utc:
            raise ValueError(f"{name} certificate has expired")

    # -- Signature chain --
    _verify_signed_by(intermediate_cert, root_cert, "Intermediate CA", "Root CA")
    _verify_signed_by(pisp_ca_cert, intermediate_cert, "PISP CA", "Intermediate CA")
    _verify_signed_by(leaf_cert, pisp_ca_cert, "Leaf", "PISP CA")

    # -- pathLen on PISP CA must be 0 --
    try:
        bc = pisp_ca_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not bc.ca:
            raise ValueError("PISP CA certificate is not marked as a CA")
        if bc.path_length != 0:
            raise ValueError(
                f"PISP CA pathLen must be 0, got {bc.path_length}"
            )
    except x509.ExtensionNotFound:
        raise ValueError("PISP CA certificate has no BasicConstraints extension")

    # -- Leaf must NOT be a CA --
    try:
        leaf_bc = leaf_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if leaf_bc.ca:
            raise ValueError("Leaf certificate must not be a CA")
    except x509.ExtensionNotFound:
        pass  # No BasicConstraints on leaf is acceptable


def check_crl_revocation(
    pisp_ca_cert: x509.Certificate,
    crl_der: bytes,
    intermediate_cert: x509.Certificate,
) -> None:
    """
    Check whether a PISP CA certificate has been revoked per the SA CRL.

    Parameters
    ----------
    pisp_ca_cert:      The PISP CA certificate to check.
    crl_der:           DER-encoded CRL bytes fetched from GET /scheme/crl.
    intermediate_cert: SA Intermediate CA certificate — used to verify the CRL
                       signature, preventing acceptance of a forged CRL.

    Raises
    ------
    ValueError if the CRL signature is invalid, the CRL is stale (past nextUpdate),
    or the PISP CA cert serial number appears in the revocation list.
    """
    now = _utcnow()

    crl = x509.load_der_x509_crl(crl_der)

    # Verify CRL was signed by the SA Intermediate CA
    try:
        intermediate_cert.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(crl.signature_hash_algorithm),
        )
    except Exception as exc:
        raise ValueError(f"CRL signature verification failed: {exc}") from exc

    # Reject stale CRL — must not be used past nextUpdate (RFC 5280 §6.3.3)
    if crl.next_update_utc < now:
        raise ValueError(
            f"CRL is stale: nextUpdate={crl.next_update_utc.isoformat()} is in the past"
        )

    # Check revocation: serial match in the revoked list
    revoked = crl.get_revoked_certificate_by_serial_number(pisp_ca_cert.serial_number)
    if revoked is not None:
        raise ValueError(
            f"PISP CA certificate (serial {pisp_ca_cert.serial_number:#x}) "
            f"has been revoked (revocation date: {revoked.revocation_date_utc.isoformat()})"
        )


def _verify_signed_by(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    cert_name: str,
    issuer_name: str,
) -> None:
    """Verify that cert was signed by issuer_cert's private key."""
    try:
        issuer_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    except Exception as exc:
        raise ValueError(
            f"{cert_name} certificate signature invalid (not signed by {issuer_name}): {exc}"
        )


# ---------------------------------------------------------------------------
# pisp_uri extraction
# ---------------------------------------------------------------------------

def get_pisp_uri_from_cert(cert: x509.Certificate) -> Optional[str]:
    """
    Extract the pisp_uri from a certificate's Subject Alternative Name extension.
    Returns the first URI SAN found, or None if not present.
    """
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        return uris[0] if uris else None
    except x509.ExtensionNotFound:
        return None


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def key_to_pem(
    key: ec.EllipticCurvePrivateKey,
    password: Optional[bytes] = None,
) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def cert_from_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def key_from_pem(
    pem: bytes,
    password: Optional[bytes] = None,
) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem, password=password)


# ---------------------------------------------------------------------------
# .well-known/psp-certs.json helpers
# ---------------------------------------------------------------------------

import base64
import json


def build_psp_certs_json(
    kid: str,
    leaf_cert: x509.Certificate,
    pisp_ca_cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
    root_cert: Optional[x509.Certificate] = None,
) -> dict:
    """
    Build the JSON structure for .well-known/psp-certs.json.

    The x5c array carries: leaf → PISP CA → Intermediate CA → Root CA
    (DER, base64-encoded).  Including the Root CA allows cross-PISP
    verification where peers have independent Root CAs (PoC TOFU model).
    In a production scheme the Root CA would be pre-distributed out-of-band
    and omitted here; for the PoC we include it so any PISP can verify any
    other without pre-configuration.

    Multiple keys can be present (e.g. during a rotation overlap window);
    callers can merge multiple build_psp_certs_json() results into one keys list.
    """
    def _b64(cert):
        return base64.b64encode(cert_to_der(cert)).decode()

    x5c = [_b64(leaf_cert), _b64(pisp_ca_cert), _b64(intermediate_cert)]
    if root_cert is not None:
        x5c.append(_b64(root_cert))

    return {
        "keys": [
            {
                "kid": kid,
                "alg": "ES256",
                "x5c": x5c,
            }
        ]
    }


def load_cert_chain_from_psp_certs_json(
    psp_certs: dict,
    kid: str,
) -> tuple:
    """
    Parse a .well-known/psp-certs.json response and return the cert chain
    for the given kid.

    Returns a 3-tuple (leaf_cert, pisp_ca_cert, intermediate_cert) when the
    x5c array has 3 entries, or a 4-tuple
    (leaf_cert, pisp_ca_cert, intermediate_cert, root_cert) when the x5c
    array has 4 entries (PoC cross-PISP TOFU model — root included by publisher).

    Raises KeyError if the kid is not found.
    Raises ValueError if the x5c array does not have 3 or 4 entries.
    """
    for key_entry in psp_certs.get("keys", []):
        if key_entry["kid"] == kid:
            x5c = key_entry["x5c"]
            if len(x5c) not in (3, 4):
                raise ValueError(
                    f"Expected 3 or 4 certs in x5c for kid={kid!r}, got {len(x5c)}"
                )
            certs = [
                x509.load_der_x509_certificate(base64.b64decode(b64))
                for b64 in x5c
            ]
            return tuple(certs)
    raise KeyError(f"kid={kid!r} not found in psp-certs.json")


# ---------------------------------------------------------------------------
# Convenience: full PoC PKI setup in one call (used by tests)
# ---------------------------------------------------------------------------

class PocPki:
    """
    A complete PoC PKI instance generated in-process.

    Useful for tests and for the PISP service startup when running in
    development mode without pre-generated PKI artefacts on disk.

    Usage:
        pki = PocPki.generate(pisp_uri="psp://requester-pisp.test", pisp_name="Requester PISP")
        # pki.root_cert, pki.intermediate_cert
        # pki.pisp_ca_cert, pki.pisp_ca_key
        # pki.leaf_cert, pki.leaf_key, pki.kid
        # pki.psp_certs_json   → dict ready to serve from .well-known
    """

    def __init__(
        self,
        root_key, root_cert,
        intermediate_key, intermediate_cert,
        pisp_ca_key, pisp_ca_cert,
        leaf_key, leaf_cert,
        kid: str,
        pisp_uri: str,
    ):
        self.root_key = root_key
        self.root_cert = root_cert
        self.intermediate_key = intermediate_key
        self.intermediate_cert = intermediate_cert
        self.pisp_ca_key = pisp_ca_key
        self.pisp_ca_cert = pisp_ca_cert
        self.leaf_key = leaf_key
        self.leaf_cert = leaf_cert
        self.kid = kid
        self.pisp_uri = pisp_uri
        self.psp_certs_json = build_psp_certs_json(
            kid, leaf_cert, pisp_ca_cert, intermediate_cert, root_cert
        )

    def issue_app_cert_for_public_key(
        self,
        public_key: ec.EllipticCurvePublicKey,
        app_uri: str,
        kid: str,
        lifetime_days: int = 365,
    ) -> x509.Certificate:
        """Issue an app cert signed by this PISP's CA for a caller-provided public key."""
        return issue_app_cert_for_public_key(
            self.pisp_ca_key, self.pisp_ca_cert,
            public_key, app_uri, kid, lifetime_days,
        )

    @classmethod
    def generate(
        cls,
        pisp_uri: str,
        pisp_name: str = "Test PISP",
        kid: Optional[str] = None,
        leaf_lifetime_days: int = LEAF_LIFETIME_DAYS,
    ) -> "PocPki":
        """Generate a complete PKI hierarchy for one PISP."""
        import uuid
        if kid is None:
            kid = f"leaf-{uuid.uuid4().hex[:8]}"

        root_key, root_cert = generate_root_ca()
        int_key, int_cert = generate_intermediate_ca(root_key, root_cert)
        pisp_ca_key, csr = generate_pisp_ca_key_and_csr(pisp_uri, pisp_name)
        pisp_ca_cert = sign_pisp_csr(csr, int_key, int_cert)
        leaf_key, leaf_cert = issue_leaf_cert(
            pisp_ca_key, pisp_ca_cert, kid, leaf_lifetime_days
        )
        return cls(
            root_key, root_cert,
            int_key, int_cert,
            pisp_ca_key, pisp_ca_cert,
            leaf_key, leaf_cert,
            kid, pisp_uri,
        )

    @classmethod
    def from_files(
        cls,
        ca_key_path: str,
        ca_cert_path: str,
        intermediate_cert_path: str,
        root_cert_path: str,
        pisp_uri: str,
        kid: Optional[str] = None,
        leaf_lifetime_days: int = LEAF_LIFETIME_DAYS,
    ) -> "PocPki":
        """
        Load a pre-issued PISP CA key + full cert chain from files and issue a
        fresh short-lived leaf cert.

        Used in deployed environments where the Scheme Authority has issued the
        PISP CA cert via CSR signing.  The Root and Intermediate CA keys are NOT
        required (and must NOT be present on the PISP host — only the SA holds the
        Intermediate CA key; the Root CA key is offline only).

        Unlike ``generate()``, this method produces a 3-cert x5c array in
        ``psp_certs_json`` (leaf + PISP CA + Intermediate, no Root CA).  Peers load
        the Scheme Root cert out-of-band (PSP_ROOT_CERT_FILE env var) and use it as
        the explicit trust anchor, closing the TOFU gap present in the dev-mode
        4-cert chain.

        Parameters
        ----------
        ca_key_path:             Path to the PISP CA private key PEM file.
        ca_cert_path:            Path to the PISP CA certificate PEM file.
        intermediate_cert_path:  Path to the Scheme Intermediate CA cert PEM.
        root_cert_path:          Path to the Scheme Root CA cert PEM.
        pisp_uri:                The PISP's scheme URI.
        kid:                     Key ID override (default: generated from UUID4).
        leaf_lifetime_days:      Leaf cert lifetime in days (default: 1).
        """
        import uuid as _uuid

        if kid is None:
            kid = f"leaf-{_uuid.uuid4().hex[:8]}"

        def _load_cert(path: str) -> x509.Certificate:
            return x509.load_pem_x509_certificate(Path(path).read_bytes())

        def _load_key(path: str) -> ec.EllipticCurvePrivateKey:
            return serialization.load_pem_private_key(
                Path(path).read_bytes(), password=None
            )

        root_cert         = _load_cert(root_cert_path)
        intermediate_cert = _load_cert(intermediate_cert_path)
        pisp_ca_cert      = _load_cert(ca_cert_path)
        pisp_ca_key       = _load_key(ca_key_path)

        leaf_key, leaf_cert = issue_leaf_cert(
            pisp_ca_key, pisp_ca_cert, kid, leaf_lifetime_days
        )

        instance = cls(
            root_key=None,          # Root CA key is offline — not present on PISP host
            root_cert=root_cert,
            intermediate_key=None,  # Intermediate CA key is SA-only — not present here
            intermediate_cert=intermediate_cert,
            pisp_ca_key=pisp_ca_key,
            pisp_ca_cert=pisp_ca_cert,
            leaf_key=leaf_key,
            leaf_cert=leaf_cert,
            kid=kid,
            pisp_uri=pisp_uri,
        )
        # Override psp_certs_json: serve 3-cert x5c (leaf + PISP CA + Intermediate).
        # The Scheme Root CA is loaded out-of-band by all PISP instances from
        # PSP_ROOT_CERT_FILE, so it is deliberately omitted here.  This causes
        # signing.py's verify_message() to take the else-branch (len(chain)==3),
        # using effective_root = root_cert from the verifier's own PKI — i.e. the
        # shared Scheme Root — rather than the TOFU peer root from the x5c array.
        instance.psp_certs_json = build_psp_certs_json(
            kid, leaf_cert, pisp_ca_cert, intermediate_cert,
            root_cert=None,  # intentionally omitted — 3-cert chain only
        )
        return instance
