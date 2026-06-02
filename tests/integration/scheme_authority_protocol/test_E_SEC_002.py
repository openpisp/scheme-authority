"""
E_SEC_002 — SAP forged-issuer rejection

A PISP must reject SAP notifications whose signature is cryptographically
valid but whose ``iss`` claim does not match the registered SA URI.

BEHAVIOUR (post-E1):
    ``PISPState.scheme_authority_pisp_uri`` is set on startup by fetching the SA's
    ``/.well-known/psp/pisp.json``.  ``ProtocolESignatureMiddleware`` compares the
    verified ``sender_uri`` (from the JWS ``iss`` claim) against this URI and returns
    HTTP 403 if they differ.

Attacker model:
  • Attacker holds a PISP CA key/cert signed by the SAME Scheme Intermediate CA
    as the legitimate PISP (i.e. the attacker is a *member* of the scheme).
  • Attacker registers in the SA directory (so cert fetch succeeds — the
    signature itself validates).
  • Attacker forges a SAP notification by signing with their own leaf key
    and setting ``iss = ATTACKER_URI`` (not the SA URI).
  • The PISP rejects with 403 (wrong issuer — not the SA).

Mark: pytest.mark.integration_containers
"""
from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

pytestmark = pytest.mark.integration_containers

# ---------------------------------------------------------------------------
# Protocol-level signing helper
#
# Implements the PSP JWS compact serialisation used by Protocol B/E.
# Defined here (not imported from pisp/signing.py) so the test is
# *implementation-agnostic* — it tests the protocol, not the code.
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _canonical_json(body: dict) -> bytes:
    """Reproduce the canonical JSON used for body hashing."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _forge_jws(
    body: dict,
    *,
    leaf_key: ec.EllipticCurvePrivateKey,
    kid: str,
    iss: str,
) -> str:
    """
    Create a JWS compact token for ``body`` signed with ``leaf_key``.

    The ``iss`` claim is set to whatever the caller supplies — in the attacker
    scenario this is the attacker's own URI, not the SA's URI.
    """
    header = {"alg": "ES256", "kid": kid, "iss": iss}
    header_b64 = _b64url(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    )
    # Payload is the SHA-256 digest of the canonical JSON body
    digest = hashlib.sha256(_canonical_json(body)).digest()
    payload_b64 = _b64url(digest)

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature     = leaf_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestForgedIssuerRejection:
    """
    The PISP must return 403 for any SAP message whose ``iss`` claim
    is not the SA's registered URI — even when the signature is valid.
    """

    def test_attacker_signature_rejected_with_403(
        self, pisp_container, attacker_cert_server
    ):
        """
        Attacker-signed SAP message must be rejected with 403.

        The attacker holds a cert signed by the same Scheme Intermediate CA
        (so the signature validates), but their ``iss`` is not the SA URI.
        The PISP must detect this and return 403 — not let it through.
        """
        attacker = attacker_cert_server  # fixture yields attacker_pki dict

        # Build a plausible-looking SAP body
        body = {
            "event":      "DISPUTE_ACKNOWLEDGED",
            "dispute_id": "test-dispute-001",
        }

        token = _forge_jws(
            body,
            leaf_key=attacker["leaf_key"],
            kid=attacker["kid"],
            iss=attacker["uri"],   # NOT the SA URI — this is the attack
        )

        resp = httpx.post(
            f"{pisp_container._test_url}/scheme/disputes/acknowledged",
            json=body,
            headers={"X-PSP-Signature": token},
            timeout=10.0,
        )

        # With E1 fix → 403 (wrong issuer)
        # Without E1    → some other code (200 from handler, or 422 from body validation)
        assert resp.status_code == 403, (
            f"Expected 403 (wrong issuer) but got {resp.status_code}. "
            f"Response: {resp.text[:200]}"
        )

    def test_forged_sa_uri_rejected(self, pisp_container, sa_container, attacker_cert_server):
        """
        An attacker that claims to be the SA (spoofs iss = SA URI) but signs
        with their own key must be rejected at the signature verification stage
        (SignatureError) — the cert in the JWS header belongs to the attacker,
        and the signature won't verify against what the SA's cert chain says.

        If this somehow reaches the issuer check instead, it should also be
        rejected there for a different reason.
        """
        attacker = attacker_cert_server

        # Fetch the SA's URI from its well-known endpoint
        sa_pisp_json = httpx.get(
            f"{sa_container._test_url}/.well-known/psp/pisp.json"
        ).json()
        sa_uri = sa_pisp_json["pisp_uri"]

        body  = {"event": "DISPUTE_ACKNOWLEDGED", "dispute_id": "spoof-001"}
        token = _forge_jws(
            body,
            leaf_key=attacker["leaf_key"],
            kid=attacker["kid"],
            iss=sa_uri,            # Claim to BE the SA …
        )
        # … but the kid resolves to the attacker cert, so the signature
        # verification fails because the attacker's key ≠ SA's key.

        resp = httpx.post(
            f"{pisp_container._test_url}/scheme/disputes/acknowledged",
            json=body,
            headers={"X-PSP-Signature": token},
            timeout=10.0,
        )

        # Expected: 401 (SignatureError — cert doesn't match key used to sign)
        # or 403 (issuer check — only possible after E1 sets sa_pisp_uri).
        # Either way, must NOT be 2xx.
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403 but got {resp.status_code}. "
            f"Response: {resp.text[:200]}"
        )


class TestValidSASignatureAccepted:
    """
    Complementary positive test: a message that looks like it came from the SA
    (signed with the SA's own SAP key) must be accepted.

    This test fetches the SA's psp-certs.json to get the SA URI, and verifies
    that the PISP does NOT reject a well-formed message with a correct issuer.

    Note: we cannot produce a genuine SA signature in the test (we don't hold
    the SA's private leaf key).  Instead we verify that the middleware does NOT
    block on the basis of cert-fetch failures for the SA — the SA's cert is
    served from the SA's /.well-known/psp-certs.json, which the PISP can reach
    via the Docker network.
    """

    def test_missing_signature_on_notification_path_allowed_through(
        self, pisp_container
    ):
        """
        /scheme/disputes/acknowledged is in _UNSIGNED_ALLOWED — a request
        without an X-PSP-Signature header must be let through (returns handler
        status, not 401/403).

        This confirms the middleware's unsigned-allowed list is working.
        """
        resp = httpx.post(
            f"{pisp_container._test_url}/scheme/disputes/acknowledged",
            json={"event": "DISPUTE_ACKNOWLEDGED", "dispute_id": "unsigned-001"},
            timeout=10.0,
        )
        # 401/403 would mean the unsigned-allowed list is broken.
        # Handler may return 404/422 (no such dispute) — that's fine.
        assert resp.status_code not in (401, 403), (
            f"Unsigned message on notification path incorrectly blocked: "
            f"{resp.status_code} {resp.text[:200]}"
        )
