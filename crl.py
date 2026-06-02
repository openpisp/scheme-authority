"""
Scheme Authority — RFC 5280 X.509 CRL generation.

The CRL is signed by the Scheme Intermediate CA private key.
Compliant with RFC 5280 §5 (Certificate Revocation Lists).

Extensions included:
  - AuthorityKeyIdentifier (§5.2.1) — mandatory for CA-issued CRLs
  - CRLNumber             (§5.2.3) — monotonically increasing, required for
                                      delta-CRL support and replay detection
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def build_crl(
    intermediate_key: ec.EllipticCurvePrivateKey,
    intermediate_cert: x509.Certificate,
    revoked_entries: list[dict],
    crl_number: int,
    next_update_hours: int = 24,
) -> bytes:
    """
    Build and sign a RFC 5280 X.509 CRL.

    Parameters
    ----------
    intermediate_key:   Scheme Intermediate CA private key (signs the CRL).
    intermediate_cert:  Scheme Intermediate CA certificate (provides issuer name
                        and public key for AuthorityKeyIdentifier).
    revoked_entries:    List of ``{serial_hex: str, revoked_at: str}`` dicts for
                        every PISP CA cert that has been revoked.  An empty list
                        produces a valid CRL with no entries.
    crl_number:         Monotonically increasing integer (RFC 5280 §5.2.3).
                        Must increase by at least 1 for each new CRL issued.
    next_update_hours:  How many hours until the ``nextUpdate`` field (default 24).
                        Consumers MUST reject a CRL past its nextUpdate timestamp.

    Returns
    -------
    DER-encoded CRL bytes.  Serve with ``Content-Type: application/pkix-crl``.
    """
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=next_update_hours)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(intermediate_cert.subject)
        .last_update(now)
        .next_update(next_update)
        # AuthorityKeyIdentifier — RFC 5280 §5.2.1
        # Allows consumers to identify which CA key signed this CRL without
        # having to parse the issuer name.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_cert.public_key()
            ),
            critical=False,
        )
        # CRLNumber — RFC 5280 §5.2.3
        # Monotonically increasing; enables detection of CRL replay attacks.
        .add_extension(
            x509.CRLNumber(crl_number),
            critical=False,
        )
    )

    for entry in revoked_entries:
        serial = int(entry["serial_hex"], 16)
        revoked_at = datetime.fromisoformat(entry["revoked_at"])
        # Ensure timezone-aware
        if revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(
        private_key=intermediate_key,
        algorithm=hashes.SHA256(),
    )
    return crl.public_bytes(serialization.Encoding.DER)


def load_intermediate_key(key_path: str) -> ec.EllipticCurvePrivateKey:
    """Load the Scheme Intermediate CA private key from a PEM file."""
    from pathlib import Path
    key = serialization.load_pem_private_key(
        Path(key_path).read_bytes(), password=None
    )
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(
            f"Intermediate CA key at {key_path!r} must be an EC private key, "
            f"got {type(key).__name__}"
        )
    return key


def load_intermediate_cert(cert_path: str) -> x509.Certificate:
    """Load the Scheme Intermediate CA certificate from a PEM file."""
    from pathlib import Path
    return x509.load_pem_x509_certificate(Path(cert_path).read_bytes())


# ---------------------------------------------------------------------------
# PEM-string variants  (used when key/cert is injected via environment variable
# or uploaded via the admin API rather than read from a file path)
# ---------------------------------------------------------------------------

def load_key_pem(pem: str) -> ec.EllipticCurvePrivateKey:
    """Load the Scheme Intermediate CA private key from a PEM string."""
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(
            f"Intermediate CA key must be an EC private key, got {type(key).__name__}"
        )
    return key


def load_cert_pem(pem: str) -> x509.Certificate:
    """Load an X.509 certificate from a PEM string."""
    return x509.load_pem_x509_certificate(pem.encode())
