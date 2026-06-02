"""
E_SEC_001 — SAP bootstrap security (formerly Protocol E)

Verifies that after startup:
  • Both the SA and PISP are healthy and serving their well-known endpoints.
  • The PISP has self-registered with the SA and appears as *active* in the
    Scheme directory.
  • The PISP is serving a valid .well-known/psp-certs.json with a cert chain
    that chains up to the Scheme Intermediate CA.
  • The SA is serving a valid .well-known/psp-certs.json (SAP signing
    cert for SA → PISP notifications).

These tests must pass today (before E1) — they confirm the basic PKI bootstrap
works end-to-end with real containers.

Mark: pytest.mark.integration_containers
"""
from __future__ import annotations

import base64

import httpx
import pytest
from cryptography import x509

pytestmark = pytest.mark.integration_containers


class TestHealthEndpoints:
    """Both containers must report healthy after startup."""

    def test_sa_health(self, sa_container):
        r = httpx.get(f"{sa_container._test_url}/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["component"] == "scheme-authority"
        assert body["pki_loaded"] is True, "SA must have PKI loaded from env vars"

    def test_pisp_health(self, pisp_container):
        r = httpx.get(f"{pisp_container._test_url}/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"

    def test_pisp_health_reports_correct_uri(self, pisp_container):
        from tests.integration.conftest import PISP_URI
        r = httpx.get(f"{pisp_container._test_url}/health")
        assert r.json()["pisp_uri"] == PISP_URI

    def test_pisp_signing_active_via_psp_certs(self, pisp_container):
        """Signing is enabled when the PISP serves a non-empty psp-certs.json."""
        r = httpx.get(f"{pisp_container._test_url}/.well-known/psp-certs.json")
        assert r.status_code == 200
        assert len(r.json().get("keys", [])) >= 1, (
            "PISP should serve at least one key when PSP_SIGNING_ENABLED=true"
        )


class TestSADirectory:
    """PISP must appear as active in the SA directory after self-registration."""

    def test_pisp_registered_and_active(self, sa_container, pisp_container):
        """PISP self-registration produces an active SA directory entry.

        GET /scheme/pisps/{uri} returns 200 only for active PISPs (404 otherwise).
        """
        import urllib.parse
        from tests.integration.conftest import PISP_URI

        encoded = urllib.parse.quote(PISP_URI, safe="")
        r = httpx.get(f"{sa_container._test_url}/scheme/pisps/{encoded}")
        assert r.status_code == 200, f"PISP not found or not active in SA directory: {r.text}"
        assert r.json()["psp_uri"] == PISP_URI

    def test_pisp_appears_in_directory_listing(self, sa_container, pisp_container):
        """PISP URI appears in the full SA directory listing."""
        from tests.integration.conftest import PISP_URI
        r = httpx.get(f"{sa_container._test_url}/scheme/pisps")
        assert r.status_code == 200
        uris = [entry["psp_uri"] for entry in r.json()]
        assert PISP_URI in uris


class TestPISPWellKnown:
    """PISP must serve a valid psp-certs.json with a proper cert chain."""

    def test_psp_certs_json_present(self, pisp_container):
        r = httpx.get(f"{pisp_container._test_url}/.well-known/psp-certs.json")
        assert r.status_code == 200
        body = r.json()
        assert "keys" in body
        assert len(body["keys"]) >= 1, "At least one key entry expected"

    def test_psp_certs_json_has_x5c_chain(self, pisp_container):
        r = httpx.get(f"{pisp_container._test_url}/.well-known/psp-certs.json")
        key = r.json()["keys"][0]
        assert "kid" in key
        assert "x5c" in key
        assert len(key["x5c"]) in (3, 4), (
            f"Expected 3 or 4 certs in x5c (leaf+PISP CA+Intermediate[+Root]), "
            f"got {len(key['x5c'])}"
        )

    def test_leaf_cert_subject_contains_kid(self, pisp_container):
        r = httpx.get(f"{pisp_container._test_url}/.well-known/psp-certs.json")
        key     = r.json()["keys"][0]
        kid     = key["kid"]
        leaf    = x509.load_der_x509_certificate(base64.b64decode(key["x5c"][0]))
        cn_vals = [a.value for a in leaf.subject
                   if a.oid.dotted_string == "2.5.4.3"]  # OID for commonName
        assert any(kid in cn for cn in cn_vals), (
            f"kid {kid!r} not found in leaf cert CN: {cn_vals}"
        )

    def test_pisp_ca_cert_signed_by_scheme_intermediate(
        self, pisp_container, scheme_pki
    ):
        """The PISP CA cert in the chain is signed by the Scheme Intermediate CA."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes

        r = httpx.get(f"{pisp_container._test_url}/.well-known/psp-certs.json")
        key       = r.json()["keys"][0]
        pisp_ca   = x509.load_der_x509_certificate(base64.b64decode(key["x5c"][1]))
        int_cert  = scheme_pki["int_cert"]

        # Verify the PISP CA cert signature using the Intermediate CA's public key
        try:
            int_cert.public_key().verify(
                pisp_ca.signature,
                pisp_ca.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception as exc:
            pytest.fail(
                f"PISP CA cert not signed by our Scheme Intermediate CA: {exc}"
            )


class TestSAWellKnown:
    """SA must serve its own SAP signing cert."""

    def test_sa_psp_certs_json_present(self, sa_container):
        r = httpx.get(f"{sa_container._test_url}/.well-known/psp-certs.json")
        assert r.status_code == 200
        body = r.json()
        assert "keys" in body
        assert len(body["keys"]) >= 1, "SA must expose its SAP signing key"

    def test_sa_pisp_json_role(self, sa_container):
        r = httpx.get(f"{sa_container._test_url}/.well-known/psp/pisp.json")
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == "scheme_authority"

    def test_sa_ca_chain_endpoint(self, sa_container):
        """SA must serve the CA chain for PISP bootstrap."""
        r = httpx.get(f"{sa_container._test_url}/scheme/ca-chain")
        assert r.status_code == 200
        body = r.json()
        assert "intermediate_cert_pem" in body
        assert "root_cert_pem" in body
        # Quick sanity: should start with PEM header
        assert body["intermediate_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert body["root_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
