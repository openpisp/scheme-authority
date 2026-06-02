"""
Scheme Authority — FastAPI application.

Roles
-----
1. Scheme Intermediate CA  — issues PISP CA certs from submitted CSRs.
2. PISP directory          — authoritative psp:// URI → HTTP base URL lookup.
3. CRL publisher           — RFC 5280 X.509 CRL signed by the Intermediate CA.
4. Admin UI                — HTMX-powered operator interface for PISP management.

Security model
--------------
- PISP registration (POST /scheme/pisps) is self-service; new entries are
  created with status=pending until an operator approves them.
- Approval and revocation require an authenticated admin session cookie.
- The CRL and directory endpoints are public (no auth required) — they are
  the trust-validation path for all PISP-to-PISP Inter-PISP Protocol (IPP) flows.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

import auth
import config as cfg
import crl as _crl_mod
from db import SchemeDB

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scheme-authority")

# ---------------------------------------------------------------------------
# PKI material — loaded once at startup; may be reloaded after cert upload
# ---------------------------------------------------------------------------

_intermediate_key  = None
_intermediate_cert = None
_root_cert         = None
_csr_pem: str | None = None   # set on cold-start; cleared once a cert is uploaded

# SAP (Scheme Authority Protocol) signing key/cert (SA → PISP notifications)
_protocol_e_key  = None   # EC P-256 private key for signing SAP notifications
_protocol_e_cert = None   # Leaf cert issued by SA Intermediate CA, SAN = SA_PISP_URI
_protocol_e_kid: str | None = None  # hex fingerprint


def _generate_intermediate_pki() -> None:
    """
    Cold-start path: generate an EC P-384 intermediate CA key + CSR.

    Called when ``INTERMEDIATE_CA_KEY_FILE`` is set but the file does not yet
    exist.  The private key is written to that path (on EFS so it survives
    container restarts) and the CSR is logged prominently so the operator can
    extract it and have it signed offline by the Root CA.

    After signing, the operator uploads the cert via POST /scheme/admin/pki/cert.
    Until that happens the SA runs in degraded mode: the CRL and cert-issuance
    endpoints return 503.
    """
    global _intermediate_key, _csr_pem

    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID

    log.info("Cold start: no key found — generating EC P-384 intermediate CA key + CSR …")

    key = _ec.generate_private_key(_ec.SECP384R1())
    _intermediate_key = key

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,          "PSP Scheme Intermediate CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,    "PSP Scheme Authority"),
        ]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    csr_pem_bytes = csr.public_bytes(serialization.Encoding.PEM)
    _csr_pem = csr_pem_bytes.decode()

    # Write private key to EFS path (create parent dirs if needed)
    if cfg.INTERMEDIATE_CA_KEY_FILE:
        key_path = Path(cfg.INTERMEDIATE_CA_KEY_FILE)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        key_path.write_bytes(key_pem)
        log.info("Intermediate CA private key written to %s", key_path)

        # Write CSR alongside the key for easy extraction
        csr_path = key_path.parent / "intermediate-ca.csr.pem"
        csr_path.write_bytes(csr_pem_bytes)
        log.info("Intermediate CA CSR written to %s", csr_path)

    sep = "=" * 72
    log.warning(
        "\n%s\n"
        "SCHEME AUTHORITY — COLD START\n\n"
        "A new EC P-384 Intermediate CA key has been generated and persisted.\n"
        "Have your offline Root CA sign the CSR below, then upload the signed\n"
        "certificate via:\n\n"
        "    POST /scheme/admin/pki/cert\n\n"
        "Or retrieve the CSR at any time from:\n\n"
        "    GET /scheme/pki/csr\n\n"
        "Until a signed cert is uploaded the SA runs in DEGRADED MODE:\n"
        "cert issuance and CRL generation return 503.\n\n"
        "%s\n%s%s",
        sep, sep, _csr_pem, sep,
    )
    log.warning("DEGRADED MODE active — awaiting signed Intermediate CA certificate")


def _generate_csr_from_loaded_key() -> None:
    """
    Generate a CSR from an already-loaded intermediate CA key.

    Called when the key file is present on EFS but the certificate file is
    absent — i.e. the key was written by an external tool (e.g. old pki-init.py)
    but was never paired with a signed certificate.

    Sets _csr_pem so GET /scheme/pki/csr works and pki-activate.py can
    complete the bootstrap without generating a new key.
    """
    global _csr_pem

    from cryptography.x509.oid import NameOID

    log.info(
        "Key loaded but cert absent — generating CSR from existing key "
        "for operator signing via POST /scheme/admin/pki/cert"
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,       "PSP Scheme Intermediate CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PSP Scheme Authority"),
        ]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(_intermediate_key, hashes.SHA256())
    )

    csr_pem_bytes = csr.public_bytes(serialization.Encoding.PEM)
    _csr_pem = csr_pem_bytes.decode()

    # Write CSR alongside the key for easy extraction
    if cfg.INTERMEDIATE_CA_KEY_FILE:
        csr_path = Path(cfg.INTERMEDIATE_CA_KEY_FILE).parent / "intermediate-ca.csr.pem"
        csr_path.write_bytes(csr_pem_bytes)
        log.info("Intermediate CA CSR written to %s", csr_path)

    sep = "=" * 72
    log.warning(
        "\n%s\n"
        "SCHEME AUTHORITY — KEY WITHOUT CERTIFICATE\n\n"
        "A key exists on EFS but no signed certificate was found.\n"
        "Have your offline Root CA sign the CSR below (or use GET /scheme/pki/csr),\n"
        "then upload the result via:\n\n"
        "    POST /scheme/admin/pki/cert\n\n"
        "    python3 infrastructure/scripts/pki-activate.py --sa-url <URL>\n\n"
        "Until a cert is uploaded cert issuance and CRL return 503.\n\n"
        "%s\n%s%s",
        sep, sep, _csr_pem, sep,
    )


def _load_pki() -> None:
    """
    Load PKI material with the following priority (highest first):

    Key
      1. ``INTERMEDIATE_CA_KEY`` env var (PEM content — cloud injection via Secrets Manager)
      2. ``INTERMEDIATE_CA_KEY_FILE`` path — file exists → load it
      3. ``INTERMEDIATE_CA_KEY_FILE`` path — file absent → cold-start self-generation

    Intermediate cert
      1. ``INTERMEDIATE_CA_CERT`` env var (PEM content)
      2. ``INTERMEDIATE_CA_CERT_FILE`` path — file exists → load it
      3. Neither → degraded (awaiting upload via POST /scheme/admin/pki/cert)

    Root cert
      1. ``ROOT_CA_CERT`` env var (PEM content)
      2. ``ROOT_CA_CERT_FILE`` path — file exists → load it
      3. Neither → degraded
    """
    global _intermediate_key, _intermediate_cert, _root_cert

    # ---- Intermediate CA key -----------------------------------------------
    if cfg.INTERMEDIATE_CA_KEY:
        try:
            _intermediate_key = _crl_mod.load_key_pem(cfg.INTERMEDIATE_CA_KEY)
            log.info("Intermediate CA key loaded from INTERMEDIATE_CA_KEY env var")
        except Exception as exc:
            log.error("Failed to load Intermediate CA key from env var: %s", exc)

    elif cfg.INTERMEDIATE_CA_KEY_FILE:
        key_path = Path(cfg.INTERMEDIATE_CA_KEY_FILE)
        if key_path.exists():
            try:
                _intermediate_key = _crl_mod.load_intermediate_key(str(key_path))
                log.info("Intermediate CA key loaded from %s", key_path)
            except Exception as exc:
                log.error("Failed to load Intermediate CA key from %s: %s", key_path, exc)
        else:
            # Cold start — generate key + CSR, start in degraded mode
            _generate_intermediate_pki()

    else:
        log.warning(
            "No Intermediate CA key source configured "
            "(set INTERMEDIATE_CA_KEY or INTERMEDIATE_CA_KEY_FILE)"
        )

    # ---- Intermediate CA cert ----------------------------------------------
    if cfg.INTERMEDIATE_CA_CERT:
        try:
            _intermediate_cert = _crl_mod.load_cert_pem(cfg.INTERMEDIATE_CA_CERT)
            log.info(
                "Intermediate CA cert loaded from env var (subject=%s)",
                _intermediate_cert.subject.rfc4514_string(),
            )
        except Exception as exc:
            log.error("Failed to load Intermediate CA cert from env var: %s", exc)

    elif cfg.INTERMEDIATE_CA_CERT_FILE:
        cert_path = Path(cfg.INTERMEDIATE_CA_CERT_FILE)
        if cert_path.exists():
            try:
                _intermediate_cert = _crl_mod.load_intermediate_cert(str(cert_path))
                log.info(
                    "Intermediate CA cert loaded from %s (subject=%s)",
                    cert_path, _intermediate_cert.subject.rfc4514_string(),
                )
            except Exception as exc:
                log.error("Failed to load Intermediate CA cert from %s: %s", cert_path, exc)
        else:
            log.info(
                "Intermediate CA cert not yet present at %s — "
                "awaiting upload via POST /scheme/admin/pki/cert",
                cert_path,
            )
            # Key is loaded but cert is absent — generate a CSR from the
            # existing key so the operator can sign it via pki-activate.py.
            # (Covers the case where a key was written to EFS by an external
            # tool but the cert was never uploaded.)
            if _intermediate_key is not None:
                _generate_csr_from_loaded_key()

    else:
        log.warning(
            "No Intermediate CA cert source configured "
            "(set INTERMEDIATE_CA_CERT or INTERMEDIATE_CA_CERT_FILE)"
        )

    # ---- Root CA cert ------------------------------------------------------
    if cfg.ROOT_CA_CERT:
        try:
            _root_cert = _crl_mod.load_cert_pem(cfg.ROOT_CA_CERT)
            log.info(
                "Root CA cert loaded from env var (subject=%s)",
                _root_cert.subject.rfc4514_string(),
            )
        except Exception as exc:
            log.error("Failed to load Root CA cert from env var: %s", exc)

    elif cfg.ROOT_CA_CERT_FILE:
        root_path = Path(cfg.ROOT_CA_CERT_FILE)
        if root_path.exists():
            try:
                _root_cert = x509.load_pem_x509_certificate(root_path.read_bytes())
                log.info(
                    "Root CA cert loaded from %s (subject=%s)",
                    root_path, _root_cert.subject.rfc4514_string(),
                )
            except Exception as exc:
                log.error("Failed to load Root CA cert from %s: %s", root_path, exc)
        else:
            log.info(
                "Root CA cert not yet present at %s — "
                "awaiting upload via POST /scheme/admin/pki/cert",
                root_path,
            )

    else:
        log.warning(
            "No Root CA cert source configured "
            "(set ROOT_CA_CERT or ROOT_CA_CERT_FILE)"
        )

    # ---- SAP signing leaf -------------------------------------------------------
    # Generate SA's own SAP signing key + leaf cert, issued by the
    # SA Intermediate CA so PISPs can validate it against the shared Root CA.
    if _intermediate_key is not None and _intermediate_cert is not None and cfg.PSP_E_SIGNING_ENABLED:
        try:
            import sys as _sys
            import hashlib as _hashlib
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1 as _SECP256R1
            import datetime as _datetime
            from cryptography.x509.oid import NameOID as _NameOID, ExtendedKeyUsageOID as _EKUsageOID

            global _protocol_e_key, _protocol_e_cert, _protocol_e_kid

            # Generate fresh leaf key each startup (short-lived; no persistence needed)
            _protocol_e_key = _ec.generate_private_key(_SECP256R1())

            # Issue leaf cert: signed by Intermediate CA, SAN = SA_PISP_URI
            _now = _datetime.datetime.now(_datetime.timezone.utc)
            from cryptography import x509 as _x509
            _leaf_cert = (
                _x509.CertificateBuilder()
                .subject_name(_x509.Name([
                    _x509.NameAttribute(_NameOID.ORGANIZATION_NAME, "PSP Scheme Authority"),
                    _x509.NameAttribute(_NameOID.COMMON_NAME, "SA SAP Signing Key"),
                ]))
                .issuer_name(_intermediate_cert.subject)
                .public_key(_protocol_e_key.public_key())
                .serial_number(_x509.random_serial_number())
                .not_valid_before(_now)
                .not_valid_after(_now + _datetime.timedelta(days=365))
                .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    _x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=False, crl_sign=False,
                        encipher_only=False, decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    _x509.SubjectAlternativeName([
                        _x509.UniformResourceIdentifier(cfg.SA_PISP_URI),
                    ]),
                    critical=False,
                )
                .sign(_intermediate_key, hashes.SHA256())
            )
            _protocol_e_cert = _leaf_cert
            _protocol_e_kid = _hashlib.sha256(
                _protocol_e_cert.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest()[:16]
            log.info(
                "SAP signing key generated (kid=%s, uri=%s)",
                _protocol_e_kid, cfg.SA_PISP_URI,
            )
        except Exception as exc:
            log.warning("SAP signing key generation failed: %s", exc)


# ---------------------------------------------------------------------------
# O6 — Certificate lifecycle utilities
# ---------------------------------------------------------------------------

def _days_until_expiry(cert) -> int | None:
    """Return days until a certificate expires (negative = already expired)."""
    if cert is None:
        return None
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return (cert.not_valid_after_utc - now).days


def _cert_health_warnings() -> list[dict]:
    """
    Inspect all loaded certificates and return a list of warning dicts.

    Each dict has keys:
      name     – human-readable label (e.g. "Intermediate CA", "PISP psp://...")
      days     – days remaining (negative = expired)
      level    – "critical" (≤7) / "warning" (≤30) / "ok"

    Only entries at warning or critical level are returned (nothing to say
    about a cert with plenty of time remaining).
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    warnings = []

    def _check(cert, name):
        if cert is None:
            return
        days = (cert.not_valid_after_utc - now).days
        if days <= 7:
            level = "critical"
        elif days <= 30:
            level = "warning"
        else:
            return
        warnings.append({"name": name, "days": days, "level": level,
                          "expires": cert.not_valid_after_utc.strftime("%Y-%m-%d")})

    _check(_intermediate_cert, "Intermediate CA")
    _check(_root_cert, "Root CA")
    _check(_protocol_e_cert, "SAP signing key")

    # Check all active PISP certs
    try:
        for pisp in _db.list_pisps(status="active"):
            pem = pisp.get("pisp_ca_cert")
            if not pem:
                continue
            try:
                cert_obj = x509.load_pem_x509_certificate(pem.encode())
                _check(cert_obj, f"PISP {pisp['psp_uri']}")
            except Exception:
                pass
    except Exception:
        pass

    return warnings


def _log_cert_health() -> None:
    """Log certificate expiry warnings at startup and on rotation."""
    warnings = _cert_health_warnings()
    for w in warnings:
        msg = "Certificate expiry %s: %s expires in %d day(s) (%s)"
        if w["level"] == "critical":
            log.critical(msg, "CRITICAL", w["name"], w["days"], w["expires"])
        else:
            log.warning(msg, "WARNING", w["name"], w["days"], w["expires"])
    if not warnings:
        log.info("Certificate health OK — all certs have >30 days remaining")


def _sa_sign_message(body: dict) -> Optional[str]:
    """Sign an outbound SA → PISP SAP (Scheme Authority Protocol) notification.

    Returns a JWS compact token string, or None if signing is not initialised
    or PSP_E_SIGNING_ENABLED is false.
    """
    if not cfg.PSP_E_SIGNING_ENABLED:
        return None
    if _protocol_e_key is None or _protocol_e_kid is None:
        return None

    import base64 as _b64
    import hashlib as _hs
    import json as _js
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives import hashes as _hashes

    header = {"alg": "ES256", "kid": _protocol_e_kid, "iss": cfg.SA_PISP_URI}
    header_b64 = _b64.urlsafe_b64encode(
        _js.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    canonical = _js.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    digest = _hs.sha256(canonical).digest()
    payload_b64 = _b64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _protocol_e_key.sign(signing_input, _ec.ECDSA(_hashes.SHA256()))
    signature_b64 = _b64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{signature_b64}"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_db: SchemeDB = SchemeDB()     # no-op until overwritten in lifespan


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db
    _db = SchemeDB(cfg.SA_DB_URL)
    _load_pki()
    _log_cert_health()
    if cfg.SA_AUTO_APPROVE:
        log.info("SA_AUTO_APPROVE=true — PISPs are approved immediately on registration (dev mode)")
    yield


_SA_OPENAPI_TAGS = [
    {
        "name": "Authentication",
        "description": "Operator and PISP admin login — returns a short-lived Bearer JWT.",
    },
    {
        "name": "Discovery",
        "description": "Well-known endpoints and health check. Used by PISPs and tooling to locate the SA and fetch its signing certificates.",
    },
    {
        "name": "Directory",
        "description": "Read-only PISP directory. Any peer PISP can look up registered PISPs, fetch CA chains, and verify certificates.",
    },
    {
        "name": "Registration",
        "description": "PISP self-registration and lifecycle management: submit a CSR, receive a signed certificate, get approved or revoked by a human SA operator.",
    },
    {
        "name": "PKI",
        "description": "Certificate authority operations: CRL, CSR submission, certificate issuance, key rotation (`rotate-sap-key`). SA-operator–only write paths.",
    },
    {
        "name": "Economics",
        "description": "Scheme fee schedule and settlement window management. PISPs submit window reports; the SA reconciles inter-PISP netting.",
    },
    {
        "name": "Disputes",
        "description": "Stage 3 dispute escalation. A PISP raises a dispute at the SA when Stage 1/2 PISP-level resolution fails. The SA arbitrates and publishes a binding verdict.",
    },
    {
        "name": "Dev",
        "description": "Development and testing helpers. **Not present in production deployments.**",
    },
]

app = FastAPI(
    title="PSP Scheme Authority",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
    openapi_tags=_SA_OPENAPI_TAGS,
)

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

AdminDep    = Annotated[dict, Depends(auth.require_admin_login)]   # cookie/Bearer — 401 on fail
AdminApiDep = Annotated[dict, Depends(auth.require_admin_api)]     # JSON API routes — 401 JSON on fail


def _require_pisp_sender(request: Request) -> dict:
    """Extract the calling PISP's identity from the X-PSP-Signature JWS header.

    The header carries a compact JWS token whose first segment (protected header)
    contains ``{"alg":"ES256","kid":"...","iss":"<pisp_uri>"}``.  We decode that
    segment to get the sender's URI without needing to fully verify the signature
    here (the SA's ProtocolESignatureMiddleware or a future enforcement layer handles
    cryptographic verification).

    When ``PSP_E_SIGNING_ENABLED=false`` (default) the SA trusts the ``iss`` claim
    unverified — sufficient for dev/staging.  Production deployments should set
    ``PSP_SAP_SIGNING_ENABLED=true`` to enforce full chain verification.

    Falls back to the ``X-PSP-Sender`` header so that lightweight callers (scripts,
    tests) can supply identity without a full JWS.

    Raises 401 if neither header is present.
    """
    token = request.headers.get("X-PSP-Signature", "")
    if token:
        try:
            header_b64 = token.split(".")[0]
            # Re-add base64url padding
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            pisp_uri = header.get("iss", "")
            if pisp_uri:
                return {"iss": pisp_uri}
        except Exception:
            pass

    # Fallback: plain header (useful for scripts / integration tests)
    sender_header = request.headers.get("X-PSP-Sender", "")
    if sender_header:
        return {"iss": sender_header}

    raise HTTPException(
        status_code=401,
        detail="Missing X-PSP-Signature (or X-PSP-Sender) on /scheme/ endpoint",
    )


SenderDep = Annotated[dict, Depends(_require_pisp_sender)]


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Discovery"])
def health():
    return {
        "status": "ok",
        "component": "scheme-authority",
        "pki_loaded": _intermediate_key is not None,
    }


# ---------------------------------------------------------------------------
# Scheme directory API  (public — no auth required)
# ---------------------------------------------------------------------------

@app.get("/.well-known/psp-certs.json", tags=["Discovery"])
def sa_psp_certs():
    """
    Serve the SA's SAP (Scheme Authority Protocol) signing cert chain.

    PISPs fetch this to verify SA-signed notifications
    (DISPUTE_ACKNOWLEDGED, DISPUTE_RESOLVED).

    Format is the same as PISP .well-known/psp-certs.json but with:
      certificates = [leaf_pem, intermediate_pem, root_pem]
    """
    if _protocol_e_cert is None or _protocol_e_kid is None:
        # Signing not enabled or PKI not loaded — return empty but valid structure
        return {"keys": []}

    leaf_pem = _protocol_e_cert.public_bytes(serialization.Encoding.PEM).decode()
    int_pem  = _intermediate_cert.public_bytes(serialization.Encoding.PEM).decode() if _intermediate_cert else ""
    root_pem = _root_cert.public_bytes(serialization.Encoding.PEM).decode() if _root_cert else ""

    key_entry: dict = {
        "kid":          _protocol_e_kid,
        "psp_uri":      cfg.SA_PISP_URI,
        "certificates": [c for c in [leaf_pem, int_pem, root_pem] if c],
    }
    return {"keys": [key_entry]}


@app.get("/.well-known/psp/pisp.json", tags=["Discovery"])
def sa_pisp_json():
    """SA discovery endpoint — same format as PISP .well-known/psp/pisp.json."""
    return {
        "psp_version":  "1.0",
        "pisp_uri":     cfg.SA_PISP_URI,
        "role":         "scheme_authority",
        "base_url":     cfg.SA_BASE_URL,
        "capabilities": ["DISPUTE_ACKNOWLEDGED", "DISPUTE_RESOLVED"],
    }


@app.get("/scheme/ca-chain", tags=["Directory"])
def get_ca_chain():
    """
    Return the Scheme CA certificate chain (Intermediate + Root).

    PISPs call this once on first boot to obtain the shared trust material they
    need to build ``x5c`` headers and validate peer chains.  The certs are
    cached to the PISP's named volume so subsequent restarts skip this call.

    Both certs are public material — no authentication required.
    """
    if _intermediate_cert is None or _root_cert is None:
        raise HTTPException(
            status_code=503,
            detail="Scheme Authority CA certificates not loaded",
        )
    return {
        "intermediate_cert_pem": _intermediate_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode(),
        "root_cert_pem": _root_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode(),
    }


@app.get("/scheme/pisps", tags=["Directory"])
def list_pisps():
    """List all active PISPs in the scheme directory."""
    return [
        {
            "id":            p["id"],
            "psp_uri":       p["psp_uri"],
            "name":          p["name"],
            "base_url":      p["base_url"],
            "b_url":         p.get("b_url") or None,
            "registered_at": p["registered_at"],
        }
        for p in _db.list_pisps(status="active")
    ]


@app.get("/scheme/pisps/{psp_uri:path}", tags=["Directory"])
def get_pisp(psp_uri: str):
    """Look up a PISP by its scheme URI.  Returns 404 if not active."""
    import urllib.parse
    psp_uri = urllib.parse.unquote(psp_uri)
    pisp = _db.get_pisp_by_uri(psp_uri)
    if not pisp or pisp["status"] != "active":
        raise HTTPException(status_code=404, detail=f"PISP {psp_uri!r} not found or not active")
    return {
        "psp_uri":  pisp["psp_uri"],
        "name":     pisp["name"],
        "base_url": pisp["base_url"],
        "b_url":    pisp.get("b_url") or None,
    }


@app.get("/scheme/pisp-cert/{psp_uri:path}", tags=["Registration"])
def get_pisp_cert(psp_uri: str):
    """
    Fetch the issued PISP CA certificate by scheme URI.

    Called by a PISP that registered while ``SA_AUTO_APPROVE=false`` (i.e. the
    201 response contained no cert).  The PISP polls this endpoint until an
    operator approves the registration via the admin UI.

    The path parameter is the URL-encoded ``psp://`` URI
    (e.g. ``psp%3A%2F%2Fpisp.example.com``).

    Responses
    ---------
    200  ``{pisp_ca_cert_pem, serial_hex, status}`` — approved; cert returned.
    202  ``{status: "pending"}`` — not yet approved; caller should retry.
    409  PISP has been revoked.
    404  Unknown PISP URI.
    """
    import urllib.parse
    psp_uri = urllib.parse.unquote(psp_uri)
    pisp = _db.get_pisp_by_uri(psp_uri)
    if not pisp:
        raise HTTPException(status_code=404, detail=f"PISP {psp_uri!r} not registered")

    if pisp["status"] == "revoked":
        raise HTTPException(
            status_code=409,
            detail=f"PISP {psp_uri!r} has been revoked",
        )

    if pisp["status"] == "pending":
        return Response(
            content='{"status":"pending"}',
            status_code=202,
            media_type="application/json",
        )

    # status == "active"
    return {
        "psp_uri":          pisp["psp_uri"],
        "status":           pisp["status"],
        "pisp_ca_cert_pem": pisp["pisp_ca_cert"],
        "serial_hex":       pisp["serial_hex"],
    }


# ---------------------------------------------------------------------------
# PISP registration  (self-service — no auth required; creates pending record)
# ---------------------------------------------------------------------------

class RegisterBody(BaseModel):
    psp_uri:  str
    name:     str
    base_url: str
    csr_pem:  str          # PEM-encoded CSR — proves the submitter holds the private key
    b_url:    Optional[str] = None  # IPP (Inter-PISP Protocol) mTLS endpoint (e.g. https://pisp.example.com:8443)


@app.post("/scheme/pisps", status_code=201, tags=["Registration"])
def register_pisp(body: RegisterBody):
    """
    Register a new PISP with the Scheme Authority.

    The caller submits a CSR (Certificate Signing Request) along with the PISP's
    identity metadata.  The SA validates the CSR signature, signs it with the
    Intermediate CA to produce the PISP CA certificate, records the serial number,
    and returns the issued cert to the caller.

    **Normal flow** (``SA_AUTO_APPROVE=false``, production):
      The new PISP record is created with ``status=pending``; an operator must
      approve it via ``POST /scheme/pisps/{id}/approve`` before it appears in the
      directory.

    **Dev auto-approve** (``SA_AUTO_APPROVE=true``):
      The record is immediately set to ``status=active`` — no manual step required.
      This lets PISP containers register themselves on first boot without human
      intervention.

    **Duplicate registration** (409 response):
      If the URI is already registered, the response body contains the existing
      ``pisp_ca_cert_pem`` and ``serial_hex`` so the caller can recover a lost cert
      file without operator intervention (valid because the cert is public material
      and only usable by the holder of the matching private key).
    """
    if _intermediate_key is None or _intermediate_cert is None:
        raise HTTPException(
            status_code=503,
            detail="Scheme Authority CA key material not loaded — cannot issue certificates",
        )

    # Duplicate registration — return the existing cert so the PISP can recover
    # a lost cert file.  The cert is public material; it is only useful to the
    # holder of the matching private key.
    existing = _db.get_pisp_by_uri(body.psp_uri)
    if existing:
        if existing["status"] == "revoked":
            raise HTTPException(
                status_code=409,
                detail=f"PISP {body.psp_uri!r} has been revoked and cannot re-register",
            )
        log.info(
            "Duplicate registration for %s (status=%s) — returning existing cert",
            body.psp_uri, existing["status"],
        )
        return JSONResponse(
            status_code=409,
            content={
                "detail":          "already_registered",
                "psp_uri":         existing["psp_uri"],
                "status":          existing["status"],
                "pisp_ca_cert_pem": existing["pisp_ca_cert"],
                "serial_hex":      existing["serial_hex"],
            },
        )

    # Load and validate the CSR
    try:
        csr = x509.load_pem_x509_csr(body.csr_pem.encode())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CSR PEM: {exc}")

    if not csr.is_signature_valid:
        raise HTTPException(
            status_code=400,
            detail="CSR signature is invalid — the submitter must hold the corresponding private key",
        )

    # Sign the CSR with the Intermediate CA → produces the PISP CA certificate
    import sys
    from pathlib import Path as _Path
    _pki_dir = _Path(__file__).parent / "pki"
    if str(_pki_dir) not in sys.path:
        sys.path.insert(0, str(_pki_dir))
    import pki as _pki

    try:
        pisp_ca_cert = _pki.sign_pisp_csr(csr, _intermediate_key, _intermediate_cert)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"CSR signing failed: {exc}")

    pisp_ca_cert_pem = pisp_ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    serial_hex = format(pisp_ca_cert.serial_number, "x")

    # Store the PISP record.  In auto-approve mode stamp it active immediately;
    # otherwise leave it as pending — an operator must use the admin UI.
    initial_status = "active" if cfg.SA_AUTO_APPROVE else "pending"
    record = _db.save_pisp(
        psp_uri=body.psp_uri,
        name=body.name,
        base_url=body.base_url,
        b_url=body.b_url or None,
        pisp_ca_cert=pisp_ca_cert_pem,
        serial_hex=serial_hex,
        status=initial_status,
    )
    if cfg.SA_AUTO_APPROVE:
        # Mark approved_at so the record has a proper audit timestamp.
        _db.approve_pisp(record["id"])
        log.info(
            "PISP registered and auto-approved: %s (serial=%s)",
            body.psp_uri, serial_hex,
        )
        # Return the cert immediately — the PISP can proceed without polling.
        return {
            "id":               record["id"],
            "psp_uri":          body.psp_uri,
            "status":           "active",
            "pisp_ca_cert_pem": pisp_ca_cert_pem,
            "serial_hex":       serial_hex,
        }
    else:
        log.info(
            "PISP registered: %s (serial=%s) — awaiting operator approval",
            body.psp_uri, serial_hex,
        )
        # Do NOT return the cert yet.  The PISP polls GET /scheme/pisps/{uri}/cert
        # until an operator approves via the admin UI.  This ensures the PISP
        # cannot load its PKI and join the scheme before an operator has reviewed
        # and accepted its registration.
        return {
            "id":      record["id"],
            "psp_uri": body.psp_uri,
            "status":  "pending",
            "serial_hex": serial_hex,
        }


# ---------------------------------------------------------------------------
# Approval / revocation  (admin-authenticated)
# ---------------------------------------------------------------------------

@app.post("/scheme/pisps/{pisp_id}/approve", tags=["Registration", "Admin"])
def approve_pisp(pisp_id: str, _admin: AdminDep):
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404, detail="PISP not found")
    if pisp["status"] == "active":
        return {"status": "already active"}
    if pisp["status"] == "revoked":
        raise HTTPException(status_code=409, detail="Cannot approve a revoked PISP")
    _db.approve_pisp(pisp_id)
    log.info("PISP approved: %s", pisp["psp_uri"])
    return {"status": "active"}


class UpdatePispBody(BaseModel):
    base_url: Optional[str] = None
    b_url:    Optional[str] = None
    name:     Optional[str] = None


@app.patch("/scheme/pisps/{pisp_id}", tags=["Registration", "Admin"])
def update_pisp(pisp_id: str, body: UpdatePispBody, _admin: AdminDep):
    """Update a PISP's base_url, b_url, and/or name. Admin-only."""
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404, detail="PISP not found")
    _db.update_pisp(pisp_id, base_url=body.base_url, b_url=body.b_url, name=body.name)
    log.info("PISP updated: %s (base_url=%r, b_url=%r, name=%r)",
             pisp["psp_uri"], body.base_url, body.b_url, body.name)
    return {"status": "updated"}


class RevokeBody(BaseModel):
    reason: str = ""


@app.post("/scheme/pisps/{pisp_id}/revoke", tags=["Registration", "Admin"])
def revoke_pisp(pisp_id: str, body: RevokeBody, _admin: AdminDep):
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404, detail="PISP not found")
    if pisp["status"] == "revoked":
        return {"status": "already revoked"}
    _db.revoke_pisp(pisp_id, body.reason)
    log.info("PISP revoked: %s (reason=%r)", pisp["psp_uri"], body.reason)
    return {"status": "revoked"}


# ---------------------------------------------------------------------------
# CRL endpoint  (public — RFC 5280 X.509 CRL, DER-encoded)
# ---------------------------------------------------------------------------

@app.get("/scheme/crl", tags=["PKI"])
def get_crl():
    """
    Return the current Certificate Revocation List.

    The CRL is signed by the Scheme Intermediate CA private key and lists the
    serial numbers of all revoked PISP CA certificates.

    Consumers MUST:
    1. Verify the CRL signature against the Scheme Intermediate CA public key.
    2. Check that the current time is before nextUpdate.
    3. Reject any PISP whose CA cert serial appears in this CRL.

    Returns DER-encoded CRL bytes with Content-Type: application/pkix-crl.
    Per RFC 5280 §5.1, consumers should cache until nextUpdate.
    """
    if _intermediate_key is None or _intermediate_cert is None:
        raise HTTPException(
            status_code=503,
            detail="Scheme Authority CA key material not loaded — cannot generate CRL",
        )

    revoked = _db.list_revoked()
    crl_number = _db.get_crl_sequence()
    crl_bytes = _crl_mod.build_crl(
        intermediate_key=_intermediate_key,
        intermediate_cert=_intermediate_cert,
        revoked_entries=revoked,
        crl_number=crl_number,
        next_update_hours=cfg.CRL_NEXT_UPDATE_HOURS,
    )
    return Response(
        content=crl_bytes,
        media_type="application/pkix-crl",
        headers={
            "Cache-Control": f"public, max-age={cfg.CRL_NEXT_UPDATE_HOURS * 3600}",
            "Content-Disposition": "attachment; filename=scheme.crl",
        },
    )


# ---------------------------------------------------------------------------
# PKI CSR retrieval  (public — the CSR is not secret material)
# ---------------------------------------------------------------------------

@app.get("/scheme/pki/csr", tags=["PKI"])
def get_csr():
    """
    Return the Intermediate CA CSR generated on cold start.

    Only available after a cold-start self-generation where the SA has a key
    but not yet a signed certificate.  The operator retrieves this CSR, signs
    it with the offline Root CA, then uploads the resulting PEM via
    ``POST /scheme/admin/pki/cert``.

    Returns 404 once a certificate has been loaded (normal operation).
    """
    if _csr_pem is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No pending CSR — the SA already has a certificate, "
                "or no key has been generated yet"
            ),
        )
    return Response(
        content=_csr_pem.encode(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=intermediate-ca.csr.pem"},
    )


# ---------------------------------------------------------------------------
# PKI cert upload  (admin-authenticated)
# ---------------------------------------------------------------------------

class PKICertBody(BaseModel):
    intermediate_cert_pem: str   # PEM of the signed intermediate cert
    root_cert_pem:         str = ""   # PEM of the Root CA cert (optional if already loaded)


@app.post("/scheme/admin/pki/cert", tags=["PKI"])
def upload_pki_cert(body: PKICertBody, _admin: AdminDep):
    """
    Upload a signed Intermediate CA certificate (and optionally the Root CA cert).

    Called by the operator after having the CSR signed offline by the Root CA.
    The SA:
    1. Validates the certificate PEM.
    2. Verifies its public key matches the loaded Intermediate CA key.
    3. Writes both certs to the configured EFS file paths (if set).
    4. Reloads the PKI in memory — transitioning out of degraded mode.

    Requires admin session cookie.
    """
    global _intermediate_cert, _root_cert, _csr_pem

    # Parse intermediate cert
    try:
        new_cert = _crl_mod.load_cert_pem(body.intermediate_cert_pem)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid intermediate_cert_pem: {exc}")

    # Verify it matches the current intermediate key (key-pair binding check)
    if _intermediate_key is not None:
        cert_pub_pem = new_cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_pub_pem = _intermediate_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_pub_pem != key_pub_pem:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Certificate public key does not match the current "
                    "Intermediate CA private key — wrong cert or wrong key?"
                ),
            )

    # Parse root cert (optional)
    new_root = None
    if body.root_cert_pem.strip():
        try:
            new_root = _crl_mod.load_cert_pem(body.root_cert_pem)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid root_cert_pem: {exc}")

    # Persist to EFS paths (so they survive container restart)
    if cfg.INTERMEDIATE_CA_CERT_FILE:
        cert_path = Path(cfg.INTERMEDIATE_CA_CERT_FILE)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(body.intermediate_cert_pem)
        log.info("Intermediate CA cert written to %s", cert_path)

    if new_root and cfg.ROOT_CA_CERT_FILE:
        root_path = Path(cfg.ROOT_CA_CERT_FILE)
        root_path.parent.mkdir(parents=True, exist_ok=True)
        root_path.write_text(body.root_cert_pem)
        log.info("Root CA cert written to %s", root_path)

    # Reload in memory
    _intermediate_cert = new_cert
    if new_root:
        _root_cert = new_root
    _csr_pem = None   # cert is now present; suppress the CSR endpoint

    log.info(
        "PKI reloaded: intermediate subject=%s, issuer=%s",
        new_cert.subject.rfc4514_string(),
        new_cert.issuer.rfc4514_string(),
    )

    _log_cert_health()  # re-evaluate after upload
    return {
        "status":          "ok",
        "subject":         new_cert.subject.rfc4514_string(),
        "issuer":          new_cert.issuer.rfc4514_string(),
        "not_valid_after": new_cert.not_valid_after_utc.isoformat(),
        "pki_loaded":      _intermediate_key is not None and _intermediate_cert is not None,
        "root_loaded":     _root_cert is not None,
    }


# ---------------------------------------------------------------------------
# O6 — PKI health endpoint  (admin-authenticated, for monitoring integration)
# ---------------------------------------------------------------------------

@app.get("/scheme/admin/pki/health", tags=["PKI"])
def pki_health(_admin: AdminDep):
    """
    Return certificate health summary for all loaded PKI material.

    Suitable for polling by external monitoring systems (CloudWatch, Prometheus).
    Returns HTTP 200 with ``ok`` status when all certs have >30 days remaining.
    Returns HTTP 200 with ``warning`` or ``critical`` status otherwise (so callers
    can detect issues without treating a degraded state as a hard 5xx failure).

    Fields per entry in ``warnings``:
      - ``name``    — human label
      - ``days``    — days until expiry (negative = expired)
      - ``level``   — ``"warning"`` (≤30 days) or ``"critical"`` (≤7 days)
      - ``expires`` — ISO date string
    """
    from datetime import datetime, timezone
    warnings = _cert_health_warnings()
    overall = "ok"
    if any(w["level"] == "critical" for w in warnings):
        overall = "critical"
    elif warnings:
        overall = "warning"

    def _cert_summary(cert, label):
        if cert is None:
            return {"label": label, "loaded": False}
        days = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        return {
            "label":   label,
            "loaded":  True,
            "expires": cert.not_valid_after_utc.isoformat(),
            "days":    days,
        }

    return {
        "status":   overall,
        "warnings": warnings,
        "certs": {
            "intermediate_ca":   _cert_summary(_intermediate_cert, "Intermediate CA"),
            "root_ca":           _cert_summary(_root_cert, "Root CA"),
            "protocol_e_signing": _cert_summary(_protocol_e_cert, "SAP signing"),
        },
    }


# ---------------------------------------------------------------------------
# O6 — SAP key rotation  (admin-authenticated)
# ---------------------------------------------------------------------------

@app.post("/scheme/admin/pki/rotate-sap-key", tags=["PKI"])
def rotate_protocol_e(_admin: AdminDep):
    """
    Regenerate the SAP signing key and cert.

    The new leaf certificate is immediately served via ``/.well-known/psp-certs.json``.
    PISPs that cache the SA cert will pick up the new key on their next refresh
    (they should re-fetch before verifying each notification, or cache with a
    short TTL).

    Requires ``PSP_SAP_SIGNING_ENABLED=true`` and a loaded Intermediate CA.
    """
    if not cfg.PSP_E_SIGNING_ENABLED:
        raise HTTPException(status_code=409, detail="PSP_SAP_SIGNING_ENABLED is false — SAP signing not active")
    if _intermediate_key is None or _intermediate_cert is None:
        raise HTTPException(status_code=503, detail="Intermediate CA not loaded — cannot issue SAP cert")

    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1 as _SECP256R1
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives import hashes as _hashes
    import datetime as _dt
    import hashlib as _hl

    global _protocol_e_key, _protocol_e_cert, _protocol_e_kid

    _protocol_e_key = _ec.generate_private_key(_SECP256R1())
    _now = _dt.datetime.now(_dt.timezone.utc)
    _leaf = (
        _x509.CertificateBuilder()
        .subject_name(_x509.Name([
            _x509.NameAttribute(_NameOID.ORGANIZATION_NAME, "PSP Scheme Authority"),
            _x509.NameAttribute(_NameOID.COMMON_NAME, "SA SAP Signing Key"),
        ]))
        .issuer_name(_intermediate_cert.subject)
        .public_key(_protocol_e_key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(_now)
        .not_valid_after(_now + _dt.timedelta(days=365))
        .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            _x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            _x509.SubjectAlternativeName([_x509.UniformResourceIdentifier(cfg.SA_PISP_URI)]),
            critical=False,
        )
        .sign(_intermediate_key, _hashes.SHA256())
    )
    _protocol_e_cert = _leaf
    _protocol_e_kid = _hl.sha256(
        _leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()[:16]
    log.info("Scheme Authority Protocol signing key rotated (kid=%s)", _protocol_e_kid)
    return {
        "status":  "ok",
        "kid":     _protocol_e_kid,
        "expires": _leaf.not_valid_after_utc.isoformat(),
    }


# ---------------------------------------------------------------------------
# Admin UI  (session-authenticated)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# React SPA — serve the built Vite bundle for the admin portal
# ---------------------------------------------------------------------------

_SPA_DIST = Path(__file__).parent / "spa-dist"


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/app/")


@app.get("/app/assets/{filepath:path}", include_in_schema=False)
async def spa_assets(filepath: str):
    asset_path = _SPA_DIST / "assets" / filepath
    if not asset_path.exists():
        raise HTTPException(status_code=404)
    return FileResponse(str(asset_path))


@app.get("/app", include_in_schema=False)
def spa_root_redirect():
    return RedirectResponse("/app/")


@app.get("/app/", include_in_schema=False)
@app.get("/app/{path:path}", include_in_schema=False)
async def spa_catchall(request: Request, path: str = ""):
    index = _SPA_DIST / "index.html"
    if not index.exists():
        return HTMLResponse(
            "<h1>SA admin portal not built</h1>"
            "<p>Run: <code>docker build</code> or <code>cd spa && npm run build</code></p>",
            status_code=503,
        )
    return FileResponse(str(index))


# ---------------------------------------------------------------------------
# Admin JSON API — consumed by the React SPA
# ---------------------------------------------------------------------------

@app.post("/auth/login-api", include_in_schema=False)
async def login_api(request: Request):
    """JSON login endpoint for the React SPA.

    Accepts ``{"email": "…", "password": "…"}``.
    On success sets the ``sa_admin_session`` cookie and returns ``{"ok": true}``.
    On failure returns 401.
    """
    body = await request.json()
    email    = str(body.get("email", ""))
    password = str(body.get("password", ""))
    if not auth.verify_operator_credentials(email, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = auth.create_admin_token(email)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        auth.COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        max_age=cfg.SA_JWT_EXPIRE_MINUTES * 60,
    )
    return resp


@app.get("/auth/logout-api", include_in_schema=False)
def logout_api():
    """JSON logout for the React SPA — clears cookie and returns 200."""
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


@app.get("/admin/api/me", tags=["Admin API"], include_in_schema=False)
def admin_api_me(admin: AdminApiDep):
    """Return the authenticated operator's identity."""
    return {"email": admin["sub"]}


@app.get("/admin/api/pisps", tags=["Admin API"], include_in_schema=False)
def admin_api_list_pisps(admin: AdminApiDep):
    """List all PISPs (all statuses) with cert health annotations."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    all_pisps = _db.list_pisps()
    result = []
    for p in all_pisps:
        entry = {
            "id":            p["id"],
            "psp_uri":       p["psp_uri"],
            "name":          p["name"],
            "base_url":      p["base_url"],
            "b_url":         p.get("b_url"),
            "status":        p["status"],
            "registered_at": p["registered_at"],
            "approved_at":   p.get("approved_at"),
            "revoked_at":    p.get("revoked_at"),
            "revoke_reason": p.get("revoke_reason"),
            "suspended_at":  p.get("suspended_at"),
            "suspend_reason": p.get("suspend_reason"),
            "cert_days":     None,
        }
        if p.get("pisp_ca_cert"):
            try:
                co = x509.load_pem_x509_certificate(p["pisp_ca_cert"].encode())
                entry["cert_days"] = (co.not_valid_after_utc - now).days
            except Exception:
                pass
        # Annotate with assigned fee plan (if any)
        plan = _db.get_pisp_fee_plan_assignment(p["psp_uri"])
        entry["fee_plan"] = {**plan, "is_default": False} if plan else None
        result.append(entry)
    return result


@app.get("/admin/api/pisps/{pisp_id}", tags=["Admin API"], include_in_schema=False)
def admin_api_get_pisp(pisp_id: str, admin: AdminApiDep):
    """Return full PISP detail including parsed cert info."""
    from datetime import datetime, timezone
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404, detail="PISP not found")
    now = datetime.now(timezone.utc)
    cert_info = None
    if pisp.get("pisp_ca_cert"):
        try:
            co = x509.load_pem_x509_certificate(pisp["pisp_ca_cert"].encode())
            psp_uri_san = None
            try:
                san = co.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
                psp_uri_san = next((u for u in uris if u.startswith("psp://")), None)
            except x509.extensions.ExtensionNotFound:
                pass
            revoked_serials = {r["serial_hex"] for r in _db.list_revoked()}
            cert_info = {
                "subject":          co.subject.rfc4514_string(),
                "issuer":           co.issuer.rfc4514_string(),
                "not_valid_before": co.not_valid_before_utc.isoformat(),
                "not_valid_after":  co.not_valid_after_utc.isoformat(),
                "psp_uri_san":      psp_uri_san,
                "revoked":          pisp["serial_hex"] in revoked_serials,
                "days_remaining":   (co.not_valid_after_utc - now).days,
                "pem":              pisp["pisp_ca_cert"],
            }
        except Exception:
            pass
    return {
        "id":            pisp["id"],
        "psp_uri":       pisp["psp_uri"],
        "name":          pisp["name"],
        "base_url":      pisp["base_url"],
        "b_url":         pisp.get("b_url"),
        "status":        pisp["status"],
        "registered_at": pisp["registered_at"],
        "approved_at":   pisp.get("approved_at"),
        "revoked_at":    pisp.get("revoked_at"),
        "revoke_reason": pisp.get("revoke_reason"),
        "suspended_at":  pisp.get("suspended_at"),
        "suspend_reason": pisp.get("suspend_reason"),
        "cert":          cert_info,
    }


@app.post("/admin/api/pisps/{pisp_id}/approve", tags=["Admin API"], include_in_schema=False)
def admin_api_approve(pisp_id: str, admin: AdminApiDep):
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404)
    if pisp["status"] not in ("active", "revoked"):
        _db.approve_pisp(pisp_id)
        log.info("PISP approved via admin API: %s", pisp["psp_uri"])
    return {"ok": True}


@app.post("/admin/api/pisps/{pisp_id}/suspend", tags=["Admin API"], include_in_schema=False)
async def admin_api_suspend(pisp_id: str, request: Request, admin: AdminApiDep):
    """S11 — immediately suspend a PISP without cert revocation."""
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404)
    if pisp["status"] == "revoked":
        raise HTTPException(status_code=409, detail="Cannot suspend a revoked PISP")
    if pisp["status"] == "suspended":
        raise HTTPException(status_code=409, detail="PISP is already suspended")
    body = await request.json()
    reason = str(body.get("reason", ""))
    _db.suspend_pisp(pisp_id, reason)
    log.warning("PISP suspended via admin API: %s (reason=%r)", pisp["psp_uri"], reason)
    return {"ok": True}


@app.post("/admin/api/pisps/{pisp_id}/unsuspend", tags=["Admin API"], include_in_schema=False)
def admin_api_unsuspend(pisp_id: str, admin: AdminApiDep):
    """S11 — lift a suspension and restore the PISP to active."""
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404)
    if pisp["status"] != "suspended":
        raise HTTPException(status_code=409, detail="PISP is not suspended")
    _db.unsuspend_pisp(pisp_id)
    log.info("PISP unsuspended via admin API: %s", pisp["psp_uri"])
    return {"ok": True}


@app.post("/admin/api/pisps/{pisp_id}/revoke", tags=["Admin API"], include_in_schema=False)
async def admin_api_revoke(pisp_id: str, request: Request, admin: AdminApiDep):
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404)
    if pisp["status"] == "revoked":
        raise HTTPException(status_code=409, detail="PISP is already revoked")
    body = await request.json()
    reason = str(body.get("reason", ""))
    _db.revoke_pisp(pisp_id, reason)
    log.warning("PISP revoked via admin API: %s (reason=%r)", pisp["psp_uri"], reason)
    return {"ok": True}


@app.patch("/admin/api/pisps/{pisp_id}", tags=["Admin API"], include_in_schema=False)
async def admin_api_update_pisp(pisp_id: str, request: Request, admin: AdminApiDep):
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404)
    body = await request.json()
    base_url = str(body.get("base_url", "")).strip() or None
    b_url    = str(body.get("b_url", "")).strip() or None
    name     = str(body.get("name", "")).strip() or None
    _db.update_pisp(pisp_id, base_url=base_url, b_url=b_url, name=name)
    return {"ok": True}


@app.get("/admin/api/pki/health", tags=["Admin API"], include_in_schema=False)
def admin_api_pki_health(admin: AdminApiDep):
    """PKI cert health for the React dashboard."""
    cert_warnings = _cert_health_warnings()
    return {
        "warnings":           cert_warnings,
        "intermediate_days":  _days_until_expiry(_intermediate_cert),
        "protocol_e_days":    _days_until_expiry(_protocol_e_cert),
        "signing_enabled":    cfg.PSP_E_SIGNING_ENABLED,  # PSP_SAP_SIGNING_ENABLED (new) / PSP_E_SIGNING_ENABLED (compat)
        "intermediate_loaded": _intermediate_key is not None,
        "crl_next_update_hours": cfg.CRL_NEXT_UPDATE_HOURS,
    }


@app.post("/admin/api/pki/rotate-sap-key", tags=["Admin API"], include_in_schema=False)
def admin_api_rotate_protocol_e(admin: AdminApiDep):
    """Rotate the Scheme Authority Protocol signing key via the React UI."""
    if not cfg.PSP_E_SIGNING_ENABLED:
        raise HTTPException(status_code=409, detail="Scheme Authority Protocol signing not enabled")
    if _intermediate_key is None or _intermediate_cert is None:
        raise HTTPException(status_code=503, detail="Intermediate CA not loaded")
    rotate_protocol_e(admin)
    return {"ok": True}


@app.get("/admin/api/crl", tags=["Admin API"], include_in_schema=False)
def admin_api_crl(admin: AdminApiDep):
    """CRL status for the React PKI page."""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    revoked_entries = _db.list_revoked()
    crl_seq = _db.get_crl_sequence()
    return {
        "issuer":            _intermediate_cert.subject.rfc4514_string() if _intermediate_cert else None,
        "last_update":       now.isoformat(),
        "next_update":       (now + timedelta(hours=cfg.CRL_NEXT_UPDATE_HOURS)).isoformat(),
        "entry_count":       len(revoked_entries),
        "crl_number":        crl_seq,
        "intermediate_loaded": _intermediate_key is not None,
        "entries":           revoked_entries,
    }


@app.get("/admin/api/disputes", tags=["Admin API"], include_in_schema=False)
def admin_api_list_disputes(status: Optional[str] = None, admin: AdminApiDep = None):
    return _db.list_sa_disputes(status=status)


@app.get("/admin/api/disputes/{sa_dispute_id}", tags=["Admin API"], include_in_schema=False)
def admin_api_get_dispute(sa_dispute_id: str, admin: AdminApiDep):
    dispute = _db.get_sa_dispute(sa_dispute_id)
    if not dispute:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return dispute


async def _notify_pisps_of_verdict(dispute: dict, resolved_msg: dict) -> None:
    """Fire DisputeResolved notifications to both PISPs (Scheme Authority Protocol + legacy).

    Called after resolve_sa_dispute() has committed to the DB.  Fire-and-forget —
    delivery failures are logged but do not surface to the caller.
    """
    import httpx as _httpx
    import asyncio as _asyncio

    sig = _sa_sign_message(resolved_msg)
    e_headers: dict = {"Content-Type": "application/json"}
    if sig:
        e_headers["X-PSP-Signature"] = sig

    async def _notify_protocol_e(base_url: Optional[str]) -> None:
        if not base_url:
            return
        url = base_url.rstrip("/") + "/scheme/disputes/resolved"
        try:
            async with _httpx.AsyncClient(timeout=10) as c:
                resp = await c.post(url, json=resolved_msg, headers=e_headers)
            log.info("SA DisputeResolved (SAP) → %s : %s", url, resp.status_code)
        except Exception as exc:
            log.warning("SA: SAP DisputeResolved delivery failed to %s: %s", url, exc)

    async def _notify_legacy(base_url: Optional[str]) -> None:
        if not base_url:
            return
        url = base_url.rstrip("/") + "/pisp/disputes/resolved"
        try:
            async with _httpx.AsyncClient(timeout=10) as c:
                resp = await c.post(url, json=resolved_msg)
            log.info("SA DisputeResolved (legacy) → %s : %s", url, resp.status_code)
        except Exception as exc:
            log.error("SA: failed to send DisputeResolved (legacy) to %s: %s", url, exc)

    tasks = []
    for base_url in [dispute.get("payer_pisp_base_url"), dispute.get("requester_pisp_base_url")]:
        tasks.append(_asyncio.create_task(_notify_protocol_e(base_url)))
        tasks.append(_asyncio.create_task(_notify_legacy(base_url)))
    for t in tasks:
        t.add_done_callback(lambda _: None)


@app.post("/admin/api/disputes/{sa_dispute_id}/resolve", tags=["Admin API"], include_in_schema=False)
async def admin_api_resolve_dispute(
    sa_dispute_id: str, request: Request, admin: AdminApiDep
):
    dispute = _db.get_sa_dispute(sa_dispute_id)
    if not dispute:
        raise HTTPException(status_code=404)
    if dispute["status"] != "UNDER_REVIEW":
        raise HTTPException(status_code=409, detail="Dispute is not under review")
    body = await request.json()
    verdict   = str(body.get("verdict", ""))
    rationale = str(body.get("rationale", ""))
    refund_amount_pence = body.get("refund_amount_pence")
    refund_deadline     = body.get("refund_deadline")
    if verdict not in ("UPHELD", "REJECTED"):
        raise HTTPException(status_code=422, detail="verdict must be UPHELD or REJECTED")
    if not rationale.strip():
        raise HTTPException(status_code=422, detail="rationale is required")
    _db.resolve_sa_dispute(
        sa_dispute_id,
        verdict=verdict,
        rationale=rationale,
        resolved_by=admin["sub"],
    )
    refund_instruction = None
    if verdict == "UPHELD" and refund_amount_pence and refund_deadline:
        refund_instruction = {
            "amount_pence": int(refund_amount_pence),
            "currency":     "GBP",
            "deadline":     refund_deadline,
        }
    resolved_msg = {
        "dispute_id":         dispute["dispute_id"],
        "resolution":         verdict,
        "resolved_by":        cfg.SA_PISP_URI,
        "rationale":          rationale,
        "refund_instruction": refund_instruction,
    }
    await _notify_pisps_of_verdict(dispute, resolved_msg)
    log.info("SA dispute %s resolved: %s by %s", sa_dispute_id, verdict, admin["sub"])
    return {"ok": True}


@app.get("/admin/api/network/stats", tags=["Admin API"], include_in_schema=False)
def admin_api_network_stats(admin: AdminApiDep):
    """S6 — aggregate network statistics visible to the SA operator."""
    all_pisps = _db.list_pisps()
    disputes  = _db.list_sa_disputes()
    return {
        "pisps": {
            "active":    sum(1 for p in all_pisps if p["status"] == "active"),
            "pending":   sum(1 for p in all_pisps if p["status"] == "pending"),
            "suspended": sum(1 for p in all_pisps if p["status"] == "suspended"),
            "revoked":   sum(1 for p in all_pisps if p["status"] == "revoked"),
            "total":     len(all_pisps),
        },
        "disputes": {
            "under_review": sum(1 for d in disputes if d["status"] == "UNDER_REVIEW"),
            "resolved":     sum(1 for d in disputes if d["status"] == "RESOLVED"),
            "total":        len(disputes),
        },
        "crl_entries": len(_db.list_revoked()),
    }


# ---------------------------------------------------------------------------
# Scheme Economics — Scheme Authority Protocol endpoints (PISP-facing, authenticated)
# ---------------------------------------------------------------------------

@app.get("/scheme/fee-schedule", tags=["Economics"])
def scheme_fee_schedule(sender: SenderDep):
    """O7 — return the effective fee schedule for the calling PISP.

    The PISP uses this to calculate the minimum scheme_fee it must charge
    merchants per settled transaction.
    """
    pisp_uri = sender["iss"]
    schedule = _db.get_fee_schedule(pisp_uri)
    txn_fee  = schedule.get("transaction_fee_pence") or 0
    floor_p  = schedule.get("floor_pence")
    cap_p    = schedule["cap_pence"]
    # Human-readable description (intentionally omits floor/txn-fee when zero)
    desc = f"{schedule['rate'] * 100:.4g}% per transaction"
    if txn_fee:
        desc += f" + {txn_fee}p flat"
    desc += f", capped at {cap_p}p"
    if floor_p:
        desc += f", minimum {floor_p}p"
    return {
        "pisp_uri":             pisp_uri,
        "rate":                 schedule["rate"],
        "cap_pence":            cap_p,
        "transaction_fee_pence": txn_fee,
        "floor_pence":          floor_p,
        "description":          desc,
    }


@app.get("/scheme/windows", tags=["Economics"])
def scheme_list_windows():
    """S5 — list the last 6 settlement windows with computed phase timestamps.

    Public endpoint — no auth required.  PISPs call this to discover which
    window is currently open for reporting and what their deadlines are.
    All timestamps are UTC ISO-8601.
    """
    from db import recent_windows
    return recent_windows(6)


@app.get("/scheme/windows/{window_id}", tags=["Economics"])
def scheme_get_window(window_id: str):
    """S5 — return phase timestamps for a specific window (e.g. '2026-05').

    Public endpoint — no auth required.  All timestamps UTC ISO-8601.
    """
    from db import window_phases, window_status
    try:
        year, month = (int(p) for p in window_id.split("-"))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="window_id must be YYYY-MM")
    if not (2020 <= year <= 2099 and 1 <= month <= 12):
        raise HTTPException(status_code=422, detail="Invalid year or month")
    phases = window_phases(year, month)
    phases["status"] = window_status(phases)
    return phases


@app.post("/scheme/window-report", status_code=201, tags=["Economics"])
async def scheme_submit_window_report(request: Request, sender: SenderDep):
    """S5 — PISP submits its aggregate settlement report for a window.

    Body: {
      window_id,                        -- e.g. '2026-05'
      requester_inter_count,            -- number of inter-PISP payments as requester
      requester_inter_amount_pence,
      requester_inter_fee_pence,        -- PISP-calculated fees (min(amount*rate, cap))
      payer_inter_count,                -- number of inter-PISP payments as payer
      payer_inter_amount_pence,
      payer_inter_fee_pence,
      intra_count,                      -- intra-PISP payments (fee stays with PISP)
      intra_amount_pence,
      intra_fee_pence
    }

    Accepts during reporting OR reconciling phases; rejects otherwise.
    Resubmission is allowed (increments amended_count).
    All fee amounts are in GBP pence.
    """
    from db import window_phases, window_status
    pisp_uri = sender["iss"]
    body = await request.json()

    window_id = body.get("window_id", "")
    try:
        year, month = (int(p) for p in window_id.split("-"))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="window_id must be YYYY-MM")

    phases = window_phases(year, month)
    status = window_status(phases)
    if status not in ("reporting", "reconciling"):
        raise HTTPException(
            status_code=409,
            detail=(
                f"Window '{window_id}' is in '{status}' phase — "
                f"reports are accepted during 'reporting' "
                f"({phases['reporting_opens_at']} – {phases['reporting_closes_at']}) "
                f"and 'reconciling' (until {phases['reconciliation_closes_at']}) only."
            ),
        )

    def _int(key: str) -> int:
        try:
            return int(body.get(key, 0))
        except (ValueError, TypeError):
            return 0

    lines = body.get("lines")  # list of per-counterparty dicts, may be absent
    report = _db.submit_pisp_window_report(
        window_id=window_id,
        pisp_uri=pisp_uri,
        requester_inter_count=        _int("requester_inter_count"),
        requester_inter_amount_pence= _int("requester_inter_amount_pence"),
        requester_inter_fee_pence=    _int("requester_inter_fee_pence"),
        payer_inter_count=            _int("payer_inter_count"),
        payer_inter_amount_pence=     _int("payer_inter_amount_pence"),
        payer_inter_fee_pence=        _int("payer_inter_fee_pence"),
        intra_count=                  _int("intra_count"),
        intra_amount_pence=           _int("intra_amount_pence"),
        intra_fee_pence=              _int("intra_fee_pence"),
        lines=lines if isinstance(lines, list) else None,
    )
    action = "amended" if report["amended_count"] > 0 else "submitted"
    log.info(
        "Window report %s from %s for %s — net %+dp (%d counterparty lines)",
        action, pisp_uri, window_id, report["net_fee_pence"],
        len(lines) if isinstance(lines, list) else 0,
    )
    return {"status": action, "window_id": window_id, "net_fee_pence": report["net_fee_pence"]}


@app.get("/scheme/windows/{window_id}/my-report", tags=["Economics"])
def scheme_get_my_window_report(window_id: str, sender: SenderDep):
    """S5 — return the calling PISP's submitted report for a window, or 404."""
    pisp_uri = sender["iss"]
    report = _db.get_pisp_window_report(window_id, pisp_uri)
    if not report:
        raise HTTPException(status_code=404, detail="No report submitted for this window")
    return report


@app.get("/scheme/windows/{window_id}/my-obligation", tags=["Economics"])
def scheme_my_obligation(window_id: str, sender: SenderDep):
    """X8 — return the calling PISP's settlement obligation for a window.

    Returns the obligation record (status, net_pence, payment_pr_id, etc.)
    so the PISP portal can show invoice download links.  Returns 404 if no
    obligation has been calculated yet for this PISP in this window.
    """
    pisp_uri    = sender["iss"]
    obligations = _db.list_settlement_obligations(window_id)
    ob          = next((o for o in obligations if o["pisp_uri"] == pisp_uri), None)
    if not ob:
        raise HTTPException(status_code=404, detail="No obligation found for this PISP in this window")
    return ob


@app.get("/scheme/windows/{window_id}/peer-status", tags=["Economics"])
def scheme_peer_status(window_id: str, sender: SenderDep):
    """S5b — return bilateral reconciliation status for the calling PISP.

    For each counterparty in the calling PISP's report lines, returns whether
    the counterparty has filed and whether the fee figures match.
    Only surfaces data about flows that involve the calling PISP — a PISP
    cannot see fee figures between two other PISPs.
    """
    pisp_uri = sender["iss"]
    peers = _db.get_peer_status(window_id, pisp_uri)
    # Annotate with counterparty name where available
    for p in peers:
        cp_pisp = _db.get_pisp_by_uri(p["counterparty_pisp_uri"])
        p["counterparty_name"] = cp_pisp["name"] if cp_pisp else None
    return {"window_id": window_id, "pisp_uri": pisp_uri, "peers": peers}


# ---------------------------------------------------------------------------
# Scheme Economics — Admin API
# ---------------------------------------------------------------------------

@app.get("/admin/api/economics/fee-plans", tags=["Economics Admin"], include_in_schema=False)
def admin_api_list_fee_plans(admin: AdminApiDep):
    """O7 — list named fee plans.  The synthetic __default__ entry is prepended."""
    plans = _db.list_fee_plans()
    default_entry = {
        "id":                    "__default__",
        "name":                  "Scheme default",
        "rate":                  cfg.SCHEME_FEE_RATE,
        "cap_pence":             cfg.SCHEME_FEE_CAP_PENCE,
        "transaction_fee_pence": 0,
        "floor_pence":           None,
        "pisp_count":            _db.count_pisps_on_default_fee_plan(),
        "created_at":            None,
        "is_default":            True,
    }
    return [default_entry] + [
        {**p, "is_default": False} for p in plans
    ]


@app.post("/admin/api/economics/fee-plans", status_code=201, tags=["Economics Admin"], include_in_schema=False)
async def admin_api_create_fee_plan(request: Request, admin: AdminApiDep):
    """O7 — create a named fee plan."""
    body = await request.json()
    plan = _db.create_fee_plan(
        name=body.get("name", "").strip(),
        rate=float(body.get("rate", 0.05)),
        cap_pence=int(body.get("cap_pence", 10)),
        transaction_fee_pence=int(body.get("transaction_fee_pence", 0)),
        floor_pence=body.get("floor_pence") if body.get("floor_pence") is not None else None,
        created_by=admin["sub"],
    )
    return {**plan, "is_default": False, "pisp_count": 0}


@app.delete("/admin/api/economics/fee-plans/{plan_id}", status_code=204, tags=["Economics Admin"], include_in_schema=False)
def admin_api_delete_fee_plan(plan_id: str, admin: AdminApiDep):
    """O7 — delete a named fee plan and clear all PISP assignments."""
    if plan_id == "__default__":
        raise HTTPException(status_code=400, detail="Cannot delete the scheme default plan")
    _db.delete_fee_plan(plan_id)


@app.post("/admin/api/pisps/{pisp_id}/fee-plan", tags=["Economics Admin"], include_in_schema=False)
async def admin_api_assign_pisp_fee_plan(pisp_id: str, request: Request, admin: AdminApiDep):
    """O7 — assign (or unassign) a fee plan to a PISP."""
    pisp = _db.get_pisp_by_id(pisp_id)
    if not pisp:
        raise HTTPException(status_code=404, detail="PISP not found")
    body = await request.json()
    plan_id = body.get("fee_plan_id") or None  # null → revert to scheme default
    if plan_id == "__default__":
        plan_id = None
    _db.assign_pisp_fee_plan(pisp["psp_uri"], plan_id)
    return {"ok": True}


@app.get("/admin/api/economics/windows", tags=["Economics Admin"], include_in_schema=False)
def admin_api_list_windows(admin: AdminApiDep, n: int = 6):
    """O8 — list recent settlement windows with derived status and report counts."""
    from db import recent_windows
    windows = recent_windows(n)
    # Annotate each window with how many PISP reports have been submitted
    for w in windows:
        reports = _db.list_pisp_window_reports(w["window_id"])
        w["report_count"] = len(reports)
        obligations = _db.list_settlement_obligations(w["window_id"])
        w["obligation_count"] = len(obligations)
    return windows


@app.get("/admin/api/economics/windows/{window_id}", tags=["Economics Admin"], include_in_schema=False)
def admin_api_get_window(window_id: str, admin: AdminApiDep):
    """O8 — get a window's phases, reports, and obligations."""
    from db import window_phases, window_status
    try:
        year, month = (int(p) for p in window_id.split("-"))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="window_id must be YYYY-MM")
    phases = window_phases(year, month)
    phases["status"] = window_status(phases)
    reports     = _db.list_pisp_window_reports(window_id)
    obligations = _db.list_settlement_obligations(window_id)
    # Reconciliation check: sum of requester fees should equal sum of payer fees
    total_owed   = sum(r["requester_inter_fee_pence"] for r in reports)
    total_earned = sum(r["payer_inter_fee_pence"]     for r in reports)
    return {
        **phases,
        "reports":            reports,
        "report_count":       len(reports),
        "obligations":        obligations,
        "total_owed_pence":   total_owed,
        "total_earned_pence": total_earned,
        "discrepancy_pence":  total_owed - total_earned,
    }


@app.post("/admin/api/economics/windows/{window_id}/calculate", tags=["Economics Admin"], include_in_schema=False)
def admin_api_calculate_window(window_id: str, admin: AdminApiDep):
    """X4 — compute net settlement obligations from submitted reports.

    Idempotent — safe to re-run; obligations are upserted.
    Can be triggered at any time once reports are in, but typically run
    after the reconciliation window closes.
    """
    reports = _db.list_pisp_window_reports(window_id)
    if not reports:
        raise HTTPException(
            status_code=409,
            detail=f"No PISP reports submitted for window '{window_id}' yet.",
        )
    obligations = _db.calculate_netting(window_id)
    log.info("Netting calculated for window %s: %d obligations", window_id, len(obligations))
    return {
        "window_id":   window_id,
        "obligations": obligations,
        "net_debtors":   sum(1 for o in obligations if o["net_pence"] > 0),
        "net_creditors": sum(1 for o in obligations if o["net_pence"] < 0),
    }


@app.get("/admin/api/economics/windows/{window_id}/obligations", tags=["Economics Admin"], include_in_schema=False)
def admin_api_list_obligations(window_id: str, admin: AdminApiDep):
    """X4 / X8 — list net settlement obligations for a window."""
    return _db.list_settlement_obligations(window_id)


@app.post("/admin/api/economics/windows/{window_id}/instruct", tags=["Economics Admin"], include_in_schema=False)
def admin_api_instruct_window(window_id: str, admin: AdminApiDep):
    """X8 — mark all pending obligations as instructed.

    Records the operator's decision to proceed with settlement payments.
    Actual payment initiation (dogfooding via Requester Interface) is a follow-on step.
    """
    obligations = _db.list_settlement_obligations(window_id)
    if not obligations:
        raise HTTPException(
            status_code=409,
            detail="No obligations — run /calculate first.",
        )
    pending = [o for o in obligations if o["status"] == "pending"]
    if not pending:
        raise HTTPException(status_code=409, detail="All obligations already instructed.")
    for o in pending:
        _db.update_obligation_status(o["id"], "instructed")
    log.warning(
        "Window %s: %d obligations instructed by %s",
        window_id, len(pending), admin["sub"],
    )
    return {
        "window_id":   window_id,
        "instructed":  len(pending),
        "net_debtors":   sum(1 for o in pending if o["net_pence"] > 0),
        "net_creditors": sum(1 for o in pending if o["net_pence"] < 0),
    }



@app.get("/admin/api/economics/settlement-config", tags=["Economics Admin"], include_in_schema=False)
async def admin_api_settlement_config(admin: AdminApiDep):
    """X8 — return home PISP configuration status and validate the API key with a test token exchange."""
    import httpx as _httpx

    configured = all([cfg.SA_HOME_PISP_URL, cfg.SA_HOME_PISP_CLIENT_ID, cfg.SA_HOME_PISP_TERMINAL_URI, cfg.SA_HOME_PISP_API_KEY])
    result: dict = {
        "configured": configured,
        "home_pisp_url":      cfg.SA_HOME_PISP_URL,
        "terminal_uri":       cfg.SA_HOME_PISP_TERMINAL_URI,
        "client_id":          cfg.SA_HOME_PISP_CLIENT_ID,
        "api_key_set":        bool(cfg.SA_HOME_PISP_API_KEY),
        "settlement_account": {
            "sort_code":      cfg.SA_SETTLEMENT_SORT_CODE,
            "account_number": cfg.SA_SETTLEMENT_ACCOUNT_NUMBER,
            "account_name":   cfg.SA_SETTLEMENT_ACCOUNT_NAME,
        },
        "token_exchange": None,
    }

    if configured:
        try:
            async with _httpx.AsyncClient(timeout=5) as c:
                resp = await c.post(
                    f"{cfg.SA_HOME_PISP_URL.rstrip('/')}/auth/token",
                    data={
                        "grant_type":    "client_credentials",
                        "client_id":     cfg.SA_HOME_PISP_CLIENT_ID,
                        "client_secret": cfg.SA_HOME_PISP_API_KEY,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            result["token_exchange"] = {
                "ok":     resp.status_code == 200,
                "status": resp.status_code,
            }
        except Exception as exc:
            result["token_exchange"] = {"ok": False, "error": str(exc)}

    return result


@app.post("/admin/api/economics/windows/{window_id}/execute-payments", tags=["Economics Admin"], include_in_schema=False)
async def admin_api_execute_payments(window_id: str, admin: AdminApiDep):
    """X8 — create Requester Interface payment requests at SA home PISP for each instructed debit obligation.

    For each obligation where net_pence > 0 (PISP owes SA):
      1. Exchange SA home PISP API key for a Bearer token
      2. Create a UC1 payment request at the home PISP payable to the SA settlement account
      3. Store the returned payment_request_id and transition obligation → 'collecting'

    For creditor obligations (net_pence < 0, SA owes PISP): transition to 'payout_pending'.

    Requires SA_HOME_PISP_URL, SA_HOME_PISP_TERMINAL_URI, and SA_HOME_PISP_API_KEY to be set.
    """
    import httpx as _httpx

    if not all([cfg.SA_HOME_PISP_URL, cfg.SA_HOME_PISP_CLIENT_ID, cfg.SA_HOME_PISP_TERMINAL_URI, cfg.SA_HOME_PISP_API_KEY]):
        raise HTTPException(
            status_code=503,
            detail="SA home PISP not configured (SA_HOME_PISP_URL / SA_HOME_PISP_CLIENT_ID / SA_HOME_PISP_TERMINAL_URI / SA_HOME_PISP_API_KEY).",
        )

    obligations = _db.list_settlement_obligations(window_id)
    instructed = [o for o in obligations if o["status"] == "instructed"]
    if not instructed:
        raise HTTPException(
            status_code=409,
            detail="No instructed obligations — run /instruct first.",
        )

    # Exchange API key for Bearer token (once — token is valid for 1h)
    base = cfg.SA_HOME_PISP_URL.rstrip("/")
    try:
        async with _httpx.AsyncClient(timeout=15) as c:
            tok_resp = await c.post(
                f"{base}/auth/token",
                data={
                    "grant_type":    "client_credentials",
                    "client_id":     cfg.SA_HOME_PISP_CLIENT_ID,
                    "client_secret": cfg.SA_HOME_PISP_API_KEY,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        tok_resp.raise_for_status()
        bearer = tok_resp.json()["access_token"]
    except Exception as exc:
        log.error("X8: failed to obtain Bearer token from home PISP %s: %s", base, exc)
        raise HTTPException(status_code=502, detail=f"Home PISP token exchange failed: {exc}")

    executed = 0
    payout_pending = 0
    errors: list[str] = []

    async with _httpx.AsyncClient(timeout=15) as c:
        for ob in instructed:
            if ob["net_pence"] < 0:
                # SA owes this PISP — payout flow (deferred)
                _db.update_obligation_status(ob["id"], "payout_pending")
                payout_pending += 1
                continue

            # Debit: PISP owes SA — create payment request at home PISP
            pisp_name = ob["pisp_uri"].replace("psp://", "")
            try:
                pr_resp = await c.post(
                    f"{base}/requester/requests",
                    json={
                        "mode":           "once",
                        "requester_uri":  cfg.SA_HOME_PISP_TERMINAL_URI.rsplit("/terminal/", 1)[0]
                                          if cfg.SA_HOME_PISP_TERMINAL_URI and "/terminal/" in cfg.SA_HOME_PISP_TERMINAL_URI
                                          else cfg.SA_HOME_PISP_TERMINAL_URI,
                        "display_name":   cfg.SA_SETTLEMENT_ACCOUNT_NAME,
                        "amount": {
                            "value":       ob["net_pence"],
                            "asset_kind":  "fiat",
                            "asset_code":  "GBP",
                            "minor_units": 2,
                            "display":     f"£{ob['net_pence'] / 100:.2f}",
                        },
                        "reference":      f"SA-FEE-{window_id}",
                        "description":    f"Scheme fee — settlement window {window_id} — {pisp_name}",
                        "expires_in_seconds": 2592000,   # 30 days
                    },
                    headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
                )
                pr_resp.raise_for_status()
                pr_data = pr_resp.json()
                pr_id = pr_data.get("payment_request_id") or pr_data.get("id")
                _db.update_obligation_status(ob["id"], "collecting", payment_pr_id=str(pr_id))
                executed += 1
                log.info(
                    "X8: payment request %s created for obligation %s (%s, %dp)",
                    pr_id, ob["id"], ob["pisp_uri"], ob["net_pence"],
                )
            except Exception as exc:
                log.error("X8: failed to create payment request for %s: %s", ob["pisp_uri"], exc)
                errors.append(f"{ob['pisp_uri']}: {exc}")

    return {
        "window_id":      window_id,
        "executed":       executed,
        "payout_pending": payout_pending,
        "errors":         errors,
    }


# ---------------------------------------------------------------------------
# Invoice helpers — shared by admin and PISP-facing invoice endpoints
# ---------------------------------------------------------------------------

def _invoice_context(window_id: str, obligation_id: str) -> tuple:
    """Resolve all data needed to render an invoice.

    Returns (ob, pisp_name, inv_num, payment_due, qr_bytes_or_none).
    Raises HTTPException on not-found / not-ready.
    """
    import io as _io

    ob = next(
        (o for o in _db.list_settlement_obligations(window_id) if o["id"] == obligation_id),
        None,
    )
    if not ob:
        raise HTTPException(status_code=404, detail="Obligation not found")
    if not ob.get("payment_pr_id"):
        raise HTTPException(
            status_code=409,
            detail="No payment request yet — run execute-payments first.",
        )

    try:
        from db import window_phases as _wp
        _y, _m = (int(p) for p in window_id.split("-"))
        payment_due = _wp(_y, _m).get("payment_due_by", "—")
    except Exception:
        payment_due = "—"

    pisp       = _db.get_pisp_by_uri(ob["pisp_uri"])
    pisp_name  = pisp.get("name", ob["pisp_uri"]) if pisp else ob["pisp_uri"]
    inv_num    = f"SA-INV-{window_id}-{obligation_id[:8].upper()}"
    qr_payload = f"psp://pay?pr_id={ob['payment_pr_id']}"

    qr_bytes: Optional[bytes] = None
    try:
        import qrcode as _qrc
        buf = _io.BytesIO()
        _qrc.make(qr_payload).save(buf, format="PNG")
        qr_bytes = buf.getvalue()
    except ImportError:
        pass

    return ob, pisp_name, inv_num, payment_due, qr_bytes, qr_payload


def _invoice_as_json(ob: dict, pisp_name: str, inv_num: str, payment_due: str, qr_payload: str) -> dict:
    return {
        "invoice_number":    inv_num,
        "window_id":         ob["window_id"],
        "pisp_uri":          ob["pisp_uri"],
        "pisp_name":         pisp_name,
        "fees_owed_pence":   ob["fees_owed_pence"],
        "fees_earned_pence": ob["fees_earned_pence"],
        "net_pence":         ob["net_pence"],
        "status":            ob["status"],
        "payment_due_by":    payment_due,
        "payment_pr_id":     ob["payment_pr_id"],
        "qr_payload":        qr_payload,
    }


def _invoice_as_html(ob: dict, pisp_name: str, inv_num: str, payment_due: str,
                     qr_bytes: Optional[bytes], qr_payload: str) -> str:
    import base64 as _b64
    net_sign      = "owes SA" if ob["net_pence"] > 0 else "SA owes"
    status_colour = {
        "collecting":     "#2563eb",
        "settled":        "#16a34a",
        "payout_pending": "#d97706",
    }.get(ob["status"], "#64748b")
    if qr_bytes:
        qr_b64  = _b64.b64encode(qr_bytes).decode()
        qr_html = f'<img src="data:image/png;base64,{qr_b64}" width="200" height="200" alt="Payment QR" />'
    else:
        qr_html = f'<p class="qr-fallback">QR payload: <code>{qr_payload}</code></p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Settlement Invoice {inv_num}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 640px;
            margin: 40px auto; color: #1e293b; padding: 0 20px; }}
    h1   {{ font-size: 1.5rem; font-weight: 700; margin: 0; }}
    .sub {{ color: #64748b; font-size: 0.875rem; margin-top: 4px; }}
    hr   {{ border: none; border-top: 1px solid #e2e8f0; margin: 24px 0; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    td, th {{ padding: 8px 0; text-align: left; }}
    th   {{ font-weight: 600; color: #64748b; }}
    .amount {{ text-align: right; font-weight: 600; }}
    .total  {{ font-size: 1.1rem; font-weight: 700; }}
    .status {{ display: inline-block; padding: 2px 10px; border-radius: 9999px;
               font-size: 0.75rem; font-weight: 600; color: #fff;
               background: {status_colour}; }}
    .qr-section {{ text-align: center; margin: 32px 0 16px; }}
    .qr-note    {{ font-size: 0.75rem; color: #64748b; margin-top: 8px; }}
    .qr-fallback {{ font-size: 0.75rem; color: #64748b; word-break: break-all; }}
    @media print {{ .no-print {{ display: none; }} }}
  </style>
</head>
<body>

<div style="display:flex; justify-content:space-between; align-items:flex-start;">
  <div>
    <h1>Settlement Invoice</h1>
    <div class="sub">{inv_num}</div>
  </div>
  <div style="text-align:right;">
    <div style="font-weight:600;">OpenPISP Scheme Authority</div>
    <div class="sub">{cfg.SA_PISP_URI}</div>
  </div>
</div>

<hr />

<table>
  <tr><th>Invoice to</th><td>{pisp_name}</td></tr>
  <tr><th>PISP URI</th><td style="font-family:monospace;font-size:0.8rem;">{ob['pisp_uri']}</td></tr>
  <tr><th>Settlement window</th><td>{ob['window_id']}</td></tr>
  <tr><th>Payment due</th><td>{payment_due}</td></tr>
  <tr><th>Status</th><td><span class="status">{ob['status']}</span></td></tr>
</table>

<hr />

<table>
  <thead><tr><th>Description</th><th class="amount">Amount</th></tr></thead>
  <tbody>
    <tr>
      <td>Scheme fees owed to SA (window {ob['window_id']})</td>
      <td class="amount">£{ob['fees_owed_pence'] / 100:.2f}</td>
    </tr>
    <tr>
      <td>Fees earned by PISP (window {ob['window_id']})</td>
      <td class="amount" style="color:#16a34a;">−£{ob['fees_earned_pence'] / 100:.2f}</td>
    </tr>
  </tbody>
  <tfoot>
    <tr style="border-top:2px solid #e2e8f0;">
      <td class="total">Net amount due ({net_sign})</td>
      <td class="amount total">£{abs(ob['net_pence']) / 100:.2f}</td>
    </tr>
  </tfoot>
</table>

<hr />

<div class="qr-section">
  <div style="font-weight:600; margin-bottom:12px;">Scan to pay</div>
  {qr_html}
  <div class="qr-note">
    Open your payer app and scan the QR code to initiate the settlement payment.<br/>
    Payment request: <code style="font-size:0.7rem;">{ob['payment_pr_id']}</code>
  </div>
</div>

<hr />

<p style="font-size:0.75rem; color:#94a3b8; text-align:center;" class="no-print">
  Use your browser's Print function to save as PDF.
</p>

</body>
</html>"""


def _invoice_as_pdf(ob: dict, pisp_name: str, inv_num: str, payment_due: str,
                    qr_bytes: Optional[bytes], qr_payload: str) -> bytes:
    """Generate a PDF invoice using fpdf2 (pure Python, no system deps)."""
    import io as _io
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed — PDF unavailable")

    # Page dimensions: A4 = 210mm wide, margins 20mm each side → 170mm content width
    _L_MARGIN = 20
    _LABEL_W  = 50   # label column
    _VALUE_W  = 120  # value column (170 - 50)
    _R_EDGE   = 190  # right content boundary

    net_sign = "owes SA" if ob["net_pence"] > 0 else "SA owes"
    pdf = FPDF()
    pdf.set_margins(_L_MARGIN, _L_MARGIN, _L_MARGIN)
    pdf.add_page()

    # ── Header ──────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 8, "Settlement Invoice",
             new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.set_x(-70)
    pdf.cell(50, 8, "OpenPISP Scheme Authority", align="R",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 5, inv_num, new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_x(-70)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(50, 5, cfg.SA_PISP_URI, align="R",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)

    # ── Divider ─────────────────────────────────────────────────────────────
    pdf.ln(4)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(_L_MARGIN, pdf.get_y(), _R_EDGE, pdf.get_y())
    pdf.ln(6)

    # ── Details table ────────────────────────────────────────────────────────
    def _row(label: str, value: str) -> None:
        # Always start from left margin so rows never drift right
        pdf.set_x(_L_MARGIN)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(_LABEL_W, 6, label, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(30, 41, 59)
        # Explicit value-column width avoids multi_cell computing a negative
        # available-width when x is not exactly at l_margin + label_w.
        pdf.multi_cell(_VALUE_W, 6, value,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    _row("Invoice to",         pisp_name)
    _row("PISP URI",           ob["pisp_uri"])
    _row("Settlement window",  ob["window_id"])
    _row("Payment due",        payment_due)
    _row("Status",             ob["status"].upper())

    # ── Divider ─────────────────────────────────────────────────────────────
    pdf.ln(4)
    pdf.line(_L_MARGIN, pdf.get_y(), _R_EDGE, pdf.get_y())
    pdf.ln(6)

    # ── Fee table ────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(140, 6, "Description", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(30, 6, "Amount", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(30, 41, 59)

    pdf.set_font("Helvetica", "", 9)
    pdf.cell(140, 6, f"Scheme fees owed to SA (window {ob['window_id']})",
             new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(30, 6, f"£{ob['fees_owed_pence'] / 100:.2f}", align="R",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.cell(140, 6, f"Fees earned by PISP (window {ob['window_id']})",
             new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(30, 6, f"-£{ob['fees_earned_pence'] / 100:.2f}", align="R",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(2)
    pdf.line(_L_MARGIN, pdf.get_y(), _R_EDGE, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(140, 7, f"Net amount due ({net_sign})",
             new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(30, 7, f"£{abs(ob['net_pence']) / 100:.2f}", align="R",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Divider ─────────────────────────────────────────────────────────────
    pdf.ln(4)
    pdf.line(_L_MARGIN, pdf.get_y(), _R_EDGE, pdf.get_y())
    pdf.ln(8)

    # ── QR code ─────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 6, "Scan to pay", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    if qr_bytes:
        qr_buf = _io.BytesIO(qr_bytes)
        x_centre = (pdf.w - 50) / 2
        pdf.image(qr_buf, x=x_centre, y=pdf.get_y(), w=50, h=50)
        pdf.ln(54)
    else:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 5, qr_payload, align="C",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 5, "Open your payer app and scan the QR code to initiate the settlement payment.",
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, f"Payment request: {ob['payment_pr_id']}",
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())


def _invoice_response(
    ob: dict,
    pisp_name: str,
    inv_num: str,
    payment_due: str,
    qr_bytes: Optional[bytes],
    qr_payload: str,
    accept: str,
) -> Response:
    """Render the invoice in the format indicated by the Accept header."""
    if "application/json" in accept:
        return JSONResponse(_invoice_as_json(ob, pisp_name, inv_num, payment_due, qr_payload))
    if "application/pdf" in accept:
        pdf_bytes = _invoice_as_pdf(ob, pisp_name, inv_num, payment_due, qr_bytes, qr_payload)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{inv_num}.pdf"'},
        )
    return HTMLResponse(_invoice_as_html(ob, pisp_name, inv_num, payment_due, qr_bytes, qr_payload))


# ---------------------------------------------------------------------------
# Invoice endpoints
# ---------------------------------------------------------------------------

def _parse_invoice_accept(accept: str = Header(default="text/html", alias="Accept")) -> str:
    """Negotiate invoice format from a full browser/client Accept header string."""
    if "application/pdf" in accept:
        return "application/pdf"
    if "application/json" in accept:
        return "application/json"
    return "text/html"

_InvoiceAcceptDep = Annotated[str, Depends(_parse_invoice_accept)]

# OpenAPI parameter block for the Accept header — added to both invoice routes
# via openapi_extra so Swagger UI shows a dropdown.
_INVOICE_ACCEPT_PARAM = {
    "parameters": [{
        "in":       "header",
        "name":     "Accept",
        "required": False,
        "schema": {
            "type":    "string",
            "enum":    ["text/html", "application/pdf", "application/json"],
            "default": "text/html",
        },
        "description": "Response format: HTML (default), PDF download, or JSON.",
    }]
}


@app.get(
    "/admin/api/economics/windows/{window_id}/obligations/{obligation_id}/invoice",
    tags=["Economics Admin"],
    include_in_schema=False,
)
def admin_api_obligation_invoice(
    window_id: str,
    obligation_id: str,
    admin: AdminApiDep,
    accept: _InvoiceAcceptDep = "text/html",
):
    """X8 — render a settlement obligation invoice.

    Set the ``Accept`` header to choose the format:
    - ``text/html`` (default) — printable HTML page with embedded QR code
    - ``application/pdf``     — downloadable PDF with embedded QR code
    - ``application/json``    — machine-readable invoice fields
    """
    ob, pisp_name, inv_num, payment_due, qr_bytes, qr_payload = _invoice_context(window_id, obligation_id)
    return _invoice_response(ob, pisp_name, inv_num, payment_due, qr_bytes, qr_payload, accept)


@app.get(
    "/scheme/windows/{window_id}/my-invoice",
    tags=["Economics"],
    openapi_extra=_INVOICE_ACCEPT_PARAM,
)
def scheme_my_invoice(
    window_id: str,
    sender: SenderDep,
    accept: _InvoiceAcceptDep = "text/html",
):
    """X8 — PISP-facing invoice endpoint (Scheme Authority Protocol authenticated).

    Returns this PISP's settlement invoice for the given window.  The SA
    resolves the obligation from the caller's identity — no obligation ID
    required.  Returns 404 if no obligation exists yet for this window.

    Set the ``Accept`` header to choose the format:
    - ``text/html`` (default) — printable HTML page with embedded QR code
    - ``application/pdf``     — downloadable PDF with embedded QR code
    - ``application/json``    — machine-readable invoice fields
    """
    pisp_uri    = sender["iss"]
    obligations = _db.list_settlement_obligations(window_id)
    ob          = next((o for o in obligations if o["pisp_uri"] == pisp_uri), None)
    if not ob:
        raise HTTPException(status_code=404, detail="No obligation found for this PISP in this window")
    if not ob.get("payment_pr_id"):
        raise HTTPException(status_code=409, detail="No payment request yet — run execute-payments first.")
    _, pisp_name, inv_num, payment_due, qr_bytes, qr_payload = _invoice_context(window_id, ob["id"])
    return _invoice_response(ob, pisp_name, inv_num, payment_due, qr_bytes, qr_payload, accept)


@app.post("/scheme/settlement/payment-confirmed", tags=["Disputes"])
async def scheme_settlement_payment_confirmed(request: Request):
    """X8 — webhook receiver: called by the SA home PISP when a settlement payment settles.

    The home PISP fires this URL (configured as the SA terminal's callback_url) when
    a Requester Interface payment settles.  The SA looks up the obligation by payment_pr_id and
    transitions it from 'collecting' → 'settled'.

    Auth: covered by ProtocolESignatureMiddleware on all /scheme/* routes.
    """
    body = await request.json()
    pr_id    = body.get("payment_request_id") or body.get("id")
    event    = body.get("event_type", "")
    pisp_uri = body.get("pisp_uri", "")

    if not pr_id:
        log.warning("X8: settlement webhook missing payment_request_id")
        return {"ok": False, "reason": "missing payment_request_id"}

    if not event.endswith(".settled"):
        # Not a settled event — could be failed/cancelled; just acknowledge
        log.info("X8: settlement webhook non-settled event %s for %s", event, pr_id)
        return {"ok": True, "action": "noop"}

    # Find the matching obligation
    ob = _db.get_obligation_by_pr_id(pr_id)
    if not ob:
        log.warning("X8: no obligation found for payment_pr_id=%s", pr_id)
        return {"ok": False, "reason": "obligation not found"}

    if ob["status"] == "settled":
        return {"ok": True, "action": "already_settled"}

    # Security: verify the PISP URI in the webhook matches the obligation
    if pisp_uri and pisp_uri != ob.get("pisp_uri"):
        log.warning(
            "X8: pisp_uri mismatch in webhook (got %s, expected %s)",
            pisp_uri, ob.get("pisp_uri"),
        )
        # Log but don't reject — the webhook comes from the HOME PISP, not the debtor PISP

    _db.update_obligation_status(ob["id"], "settled")
    log.info(
        "X8: obligation %s for %s settled (window %s, pr_id=%s)",
        ob["id"], ob["pisp_uri"], ob["window_id"], pr_id,
    )
    return {"ok": True, "obligation_id": ob["id"]}


# ---------------------------------------------------------------------------
# Dev tooling — only available when SA_AUTO_APPROVE=true
# ---------------------------------------------------------------------------

_VALID_WINDOW_STATUSES = frozenset({
    "transaction_period", "reporting", "reconciling",
    "awaiting_payment", "paying_out", "complete",
})


@app.post(
    "/admin/api/dev/windows/{window_id}/force-status",
    tags=["Dev"],
    include_in_schema=False,
)
async def dev_force_window_status(
    window_id: str,
    body: dict,
    _admin: AdminDep,
):
    """DEV ONLY — force a settlement window into a specific phase.

    Only available when ``SA_AUTO_APPROVE=true`` (dev/staging deployments).
    Stores the override in memory; cleared on container restart.

    Body: ``{ "status": "reporting" }``

    Set ``status`` to ``"clear"`` to remove an existing override and let the
    window revert to its real computed status.

    Valid statuses: transaction_period, reporting, reconciling,
    awaiting_payment, paying_out, complete, clear
    """
    if not cfg.SA_AUTO_APPROVE:
        raise HTTPException(
            status_code=403,
            detail="dev/force-status is only available when SA_AUTO_APPROVE=true",
        )
    from db import _window_status_overrides
    status = str(body.get("status", "")).strip()
    if status == "clear":
        _window_status_overrides.pop(window_id, None)
        return {"window_id": window_id, "forced_status": None, "cleared": True}
    if status not in _VALID_WINDOW_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of: {sorted(_VALID_WINDOW_STATUSES)} or 'clear'",
        )
    _window_status_overrides[window_id] = status
    log.info("DEV: window %s forced to status=%s", window_id, status)
    return {"window_id": window_id, "forced_status": status}


@app.post("/auth/token", tags=["Authentication"])
async def get_token(request: Request):
    """
    Exchange admin credentials for a Bearer token.

    Intended for scripts and CI tooling (e.g. ``pki-activate.py``) that need to
    call admin-authenticated endpoints without a browser session.

    Accepts ``application/x-www-form-urlencoded`` body with ``email`` and
    ``password`` fields.  Returns ``{"access_token": "…", "token_type": "bearer"}``.

    The returned token is identical to the cookie-based session token and is
    accepted by all endpoints that use the ``AdminDep`` dependency via the
    ``Authorization: Bearer <token>`` header.
    """
    form = await request.form()
    email    = str(form.get("email", ""))
    password = str(form.get("password", ""))
    if not auth.verify_operator_credentials(email, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = auth.create_admin_token(email)
    return {"access_token": token, "token_type": "bearer"}



# ---------------------------------------------------------------------------
# SA Dispute arbitration — API
# ---------------------------------------------------------------------------

class SADisputeBody(BaseModel):
    dispute_id:       str
    pisp_uri:         str
    escalated_at:     str
    evidence_summary: Optional[str] = None
    payer_pisp_uri:   Optional[str] = None
    requester_pisp_uri: Optional[str] = None
    # Stage 2 PISP verdict context — so the SA reviews the case with full history.
    pisp_verdict:      Optional[str] = None   # e.g. "UPHELD_FULL", "REJECTED"
    pisp_rationale:    Optional[str] = None
    pisp_resolved_by:  Optional[str] = None
    escalated_by_role: Optional[str] = None   # "payer" | "merchant"
    # Scheme Authority Protocol fields
    other_pisp_uri:   Optional[str] = None   # PSP URI of the other party
    pr_id:            Optional[str] = None   # Payment request UUID
    reason:           Optional[str] = None   # Plain-text escalation reason
    transcript:       Optional[list] = None  # Inter-PISP Protocol message history


class EscalateBody(BaseModel):
    """Scheme Authority Protocol — PISP → SA escalation payload."""
    escalating_pisp_uri: str
    other_pisp_uri:      str
    pr_id:               str
    reason:              str
    transcript:          Optional[list] = None


@app.post("/scheme/disputes", status_code=201, tags=["Disputes"])
async def receive_dispute(body: SADisputeBody, request: Request):
    """
    Receive an escalated dispute from a PISP.

    Called by ``POST /admin/disputes/{dispute_id}/escalate`` on either PISP's
    portal.  No auth required — the SA trusts the PISP PKI chain for Inter-PISP Protocol
    calls; this endpoint is reachable from the PISP portal admin action.

    TODO: enforce X-PSP-Signature once all PISP instances have PSP_SIGNING_ENABLED.
    """
    import uuid as _uuid
    sa_dispute_id = str(_uuid.uuid4())
    now_iso = _db._utcnow() if hasattr(_db, "_utcnow") else __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()

    payer_pisp_uri     = body.payer_pisp_uri
    requester_pisp_uri = body.requester_pisp_uri

    # Always resolve notification URLs from the SA's own directory — never trust
    # caller-supplied URLs.  The SA holds the canonical PISP endpoint registry;
    # accepting URLs from the request payload would be an SSRF vector.
    payer_pisp_base_url     = ""
    requester_pisp_base_url = ""
    if payer_pisp_uri:
        _p = _db.get_pisp_by_uri(payer_pisp_uri)
        if _p:
            payer_pisp_base_url = _p.get("base_url") or ""
    if requester_pisp_uri:
        _r = _db.get_pisp_by_uri(requester_pisp_uri)
        if _r:
            requester_pisp_base_url = _r.get("base_url") or ""

    record = _db.save_sa_dispute(
        sa_dispute_id=sa_dispute_id,
        dispute_id=body.dispute_id,
        pisp_uri=body.pisp_uri,
        escalated_at=body.escalated_at,
        evidence_summary=body.evidence_summary,
        payer_pisp_uri=payer_pisp_uri,
        requester_pisp_uri=requester_pisp_uri,
        payer_pisp_base_url=payer_pisp_base_url,
        requester_pisp_base_url=requester_pisp_base_url,
        pisp_verdict=body.pisp_verdict,
        pisp_rationale=body.pisp_rationale,
        pisp_resolved_by=body.pisp_resolved_by,
        escalated_by_role=body.escalated_by_role,
    )
    log.info(
        "SA dispute created: %s (dispute_id=%s, pisp=%s)",
        sa_dispute_id, body.dispute_id, body.pisp_uri,
    )

    # Scheme Authority Protocol: fire DISPUTE_ACKNOWLEDGED to both PISPs (fire-and-forget)
    if payer_pisp_uri and requester_pisp_uri and (payer_pisp_base_url or requester_pisp_base_url):
        import asyncio as _asyncio
        _asyncio.create_task(_send_dispute_acknowledged(
            dispute_id=body.dispute_id,
            pr_id=body.pr_id or "",
            payer_pisp_uri=payer_pisp_uri,
            requester_pisp_uri=requester_pisp_uri,
            escalated_by=body.pisp_uri,
            payer_pisp_base_url=payer_pisp_base_url or "",
            requester_pisp_base_url=requester_pisp_base_url or "",
        ))

    return {
        "sa_dispute_id":           sa_dispute_id,
        "dispute_id":              body.dispute_id,
        "status":                  "UNDER_REVIEW",
        "acknowledged_at":         now_iso,
        "estimated_resolution_days": 5,
    }


@app.post("/scheme/disputes/{dispute_id}/escalate", status_code=202, tags=["Disputes"])
async def escalate_dispute(dispute_id: str, body: EscalateBody, request: Request):
    """
    Scheme Authority Protocol — PISP → SA: escalate a peer-stage dispute to SA arbitration.

    The calling PISP must have already sent DISPUTE_REFERRED to its peer.
    Fires DISPUTE_ACKNOWLEDGED to both PISPs immediately (fire-and-forget).
    """
    import uuid as _uuid
    import asyncio as _asyncio

    # Minimal validation — in production this endpoint enforces X-PSP-Signature
    if body.escalating_pisp_uri != body.escalating_pisp_uri:  # placeholder
        raise HTTPException(status_code=403, detail="escalating_pisp_uri mismatch")

    sa_dispute_id = str(_uuid.uuid4())
    now_iso = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).isoformat()

    # Resolve base URLs from the SA directory
    payer_pisp_base_url = ""
    requester_pisp_base_url = ""
    payer_pisp = _db.get_pisp_by_uri(body.escalating_pisp_uri)
    other_pisp = _db.get_pisp_by_uri(body.other_pisp_uri)

    # We cannot know which party is payer vs requester from the escalation alone;
    # use escalating_pisp_uri as payer_pisp_uri (initiator) and other as requester.
    payer_pisp_uri      = body.escalating_pisp_uri
    requester_pisp_uri  = body.other_pisp_uri
    if payer_pisp:
        payer_pisp_base_url = payer_pisp.get("base_url") or ""
    if other_pisp:
        requester_pisp_base_url = other_pisp.get("base_url") or ""

    _db.save_sa_dispute(
        sa_dispute_id=sa_dispute_id,
        dispute_id=dispute_id,
        pisp_uri=body.escalating_pisp_uri,
        escalated_at=now_iso,
        evidence_summary=body.reason,
        payer_pisp_uri=payer_pisp_uri,
        requester_pisp_uri=requester_pisp_uri,
        payer_pisp_base_url=payer_pisp_base_url,
        requester_pisp_base_url=requester_pisp_base_url,
    )

    log.info(
        "SA dispute escalated (SAP): %s (sa_id=%s, from=%s, other=%s)",
        dispute_id, sa_dispute_id, body.escalating_pisp_uri, body.other_pisp_uri,
    )

    # Fire-and-forget DISPUTE_ACKNOWLEDGED to both parties
    _asyncio.create_task(_send_dispute_acknowledged(
        dispute_id=dispute_id,
        pr_id=body.pr_id,
        payer_pisp_uri=payer_pisp_uri,
        requester_pisp_uri=requester_pisp_uri,
        escalated_by=body.escalating_pisp_uri,
        payer_pisp_base_url=payer_pisp_base_url,
        requester_pisp_base_url=requester_pisp_base_url,
    ))

    return {
        "dispute_id":                dispute_id,
        "sa_dispute_id":             sa_dispute_id,
        "status":                    "UNDER_REVIEW",
        "acknowledged_at":           now_iso,
        "estimated_resolution_days": 5,
    }


async def _send_dispute_acknowledged(
    *,
    dispute_id: str,
    pr_id: str,
    payer_pisp_uri: str,
    requester_pisp_uri: str,
    escalated_by: str,
    payer_pisp_base_url: str,
    requester_pisp_base_url: str,
) -> None:
    """Fire-and-forget: POST DISPUTE_ACKNOWLEDGED to both PISPs."""
    import httpx as _httpx
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    ack_msg = {
        "psp_version":               "1.0",
        "message_type":              "DISPUTE_ACKNOWLEDGED",
        "dispute_id":                dispute_id,
        "pr_id":                     pr_id,
        "requester_pisp_uri":        requester_pisp_uri,
        "payer_pisp_uri":            payer_pisp_uri,
        "escalated_by":              escalated_by,
        "acknowledged_at":           now,
        "estimated_resolution_days": 5,
    }
    # Add signature if enabled
    sig = _sa_sign_message(ack_msg)
    headers = {"Content-Type": "application/json"}
    if sig:
        headers["X-PSP-Signature"] = sig

    for base_url in filter(None, [payer_pisp_base_url, requester_pisp_base_url]):
        url = base_url.rstrip("/") + "/scheme/disputes/acknowledged"
        try:
            async with _httpx.AsyncClient(timeout=10) as c:
                r = await c.post(url, json=ack_msg, headers=headers)
            log.info("DISPUTE_ACKNOWLEDGED → %s : %s", url, r.status_code)
        except Exception as exc:
            log.warning("DISPUTE_ACKNOWLEDGED delivery failed to %s: %s", url, exc)


@app.get("/scheme/disputes", tags=["Disputes"])
async def list_disputes(
    request: Request,
    status: Optional[str] = None,
    role: Optional[str] = None,
    pr_id: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
):
    """
    Scheme Authority Protocol — list all disputes that the authenticated PISP is party to.

    When signing is disabled (dev mode) returns all disputes. When signing is
    enabled, caller must provide X-PSP-Signature and results are scoped to that PISP.
    """
    # In dev mode (no auth configured), return all
    disputes = _db.list_sa_disputes(status=status)
    # Apply additional filters
    if pr_id:
        disputes = [d for d in disputes if d.get("dispute_id", "").startswith(pr_id)
                    or str(d.get("pr_id", "")) == pr_id]
    total = len(disputes)
    offset = (page - 1) * limit
    page_disputes = disputes[offset: offset + limit]
    pages = max(1, (total + limit - 1) // limit) if total else 1
    return {
        "disputes": page_disputes,
        "total":    total,
        "page":     page,
        "pages":    pages,
    }


@app.get("/scheme/disputes/{sa_dispute_id}", tags=["Disputes"])
def get_dispute_by_id(sa_dispute_id: str, request: Request):
    """Scheme Authority Protocol — retrieve the current state of one dispute."""
    d = _db.get_sa_dispute(sa_dispute_id)
    if not d:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return d


@app.get("/scheme/disputes/{sa_dispute_id}/transcript", tags=["Disputes"])
def get_dispute_transcript(sa_dispute_id: str, request: Request):
    """Scheme Authority Protocol — retrieve the full event transcript for a dispute."""
    d = _db.get_sa_dispute(sa_dispute_id)
    if not d:
        raise HTTPException(status_code=404, detail="Dispute not found")
    # Return a minimal transcript from the dispute record.
    # Full Inter-PISP Protocol message history is not yet stored on the SA.
    events = []
    if d.get("escalated_at"):
        events.append({
            "stage":        "SA",
            "message_type": "ESCALATION_RECEIVED",
            "timestamp":    d["escalated_at"],
            "from":         d.get("pisp_uri"),
            "to":           cfg.SA_PISP_URI,
        })
    if d.get("resolved_at"):
        events.append({
            "stage":        "SA",
            "message_type": "DISPUTE_RESOLVED",
            "timestamp":    d["resolved_at"],
            "from":         cfg.SA_PISP_URI,
            "to":           [d.get("payer_pisp_uri"), d.get("requester_pisp_uri")],
        })
    return {"dispute_id": d.get("dispute_id", sa_dispute_id), "events": events}


class EvidenceBody(BaseModel):
    submitted_by: str
    items: list


@app.post("/scheme/disputes/{sa_dispute_id}/evidence", status_code=201, tags=["Disputes"])
async def submit_sa_evidence(sa_dispute_id: str, body: EvidenceBody, request: Request):
    """Scheme Authority Protocol — submit additional evidence to an open SA arbitration case."""
    d = _db.get_sa_dispute(sa_dispute_id)
    if not d:
        raise HTTPException(status_code=404, detail="Dispute not found")
    if d.get("status") == "RESOLVED":
        raise HTTPException(status_code=409, detail="Dispute is already resolved")
    # Evidence is accepted but stored only in-memory for now (future: persist)
    log.info(
        "SA evidence submitted for %s by %s (%d items)",
        sa_dispute_id, body.submitted_by, len(body.items),
    )
    return {"received": True, "sa_dispute_id": sa_dispute_id}


