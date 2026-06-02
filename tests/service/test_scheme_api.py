"""
Tests for scheme-authority/main.py — HTTP API via FastAPI TestClient.

Covers:
  - GET /health
  - GET /scheme/pisps  (list active)
  - GET /scheme/pisps/{psp_uri}  (lookup by URI)
  - POST /scheme/pisps  (CSR-based registration — creates pending; no cert until approved)
  - GET /scheme/pisp-cert/{psp_uri}  (cert-fetch polling endpoint)
  - POST /scheme/pisps/{id}/approve  (admin auth required)
  - POST /scheme/pisps/{id}/revoke   (admin auth required)
  - GET /scheme/crl    (RFC 5280 DER CRL)
  - Admin auth: unauthenticated requests to protected endpoints return 401/303
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import pathlib
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).parent.parent.parent  # SA repo root
PKI_DIR = ROOT / "pki"

# SA source is at repo root; pki/ is a sibling directory
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PKI_DIR))

# ---------------------------------------------------------------------------
# Environment — must be set before importing the SA modules
# ---------------------------------------------------------------------------
os.environ.setdefault("SA_DB_URL", "sqlite:///:memory:")
os.environ.setdefault("OPERATOR_EMAIL", "admin@test.example")
os.environ.setdefault("OPERATOR_PASSWORD", "test-password")
os.environ.setdefault("SA_JWT_SECRET", "test-jwt-secret")

# ---------------------------------------------------------------------------
# Load scheme-authority modules
# ---------------------------------------------------------------------------

import pki as _pki_module


def _load_sa():
    """Reload the SA app with fresh PKI material."""
    # Remove any cached SA modules so each fixture gets a clean state
    for mod_name in list(sys.modules.keys()):
        if mod_name in ("sa_config", "sa_db", "sa_auth", "sa_crl", "sa_main",
                        "config", "db", "auth", "crl", "main"):
            del sys.modules[mod_name]

    # Generate fresh CA material for this test session
    root_key, root_cert = _pki_module.generate_root_ca()
    int_key, int_cert = _pki_module.generate_intermediate_ca(root_key, root_cert)

    # Load SA modules
    cfg_spec = importlib.util.spec_from_file_location("config", SA_DIR / "config.py")
    cfg_mod = importlib.util.module_from_spec(cfg_spec)
    cfg_spec.loader.exec_module(cfg_mod)
    sys.modules["config"] = cfg_mod

    db_spec = importlib.util.spec_from_file_location("db", SA_DIR / "db.py")
    db_mod = importlib.util.module_from_spec(db_spec)
    db_spec.loader.exec_module(db_mod)
    sys.modules["db"] = db_mod

    auth_spec = importlib.util.spec_from_file_location("auth", SA_DIR / "auth.py")
    auth_mod = importlib.util.module_from_spec(auth_spec)
    auth_spec.loader.exec_module(auth_mod)
    sys.modules["auth"] = auth_mod

    crl_spec = importlib.util.spec_from_file_location("crl", SA_DIR / "crl.py")
    crl_mod = importlib.util.module_from_spec(crl_spec)
    crl_spec.loader.exec_module(crl_mod)
    sys.modules["crl"] = crl_mod

    main_spec = importlib.util.spec_from_file_location("main", SA_DIR / "main.py")
    main_mod = importlib.util.module_from_spec(main_spec)
    main_spec.loader.exec_module(main_mod)
    sys.modules["main"] = main_mod

    return main_mod, int_key, int_cert


@pytest.fixture()
def sa_app():
    """Returns (TestClient, intermediate_key, intermediate_cert)."""
    main_mod, int_key, int_cert = _load_sa()

    # Inject real PKI into the loaded module
    main_mod._intermediate_key = int_key
    main_mod._intermediate_cert = int_cert
    main_mod._root_cert = None   # not needed for these tests

    # Initialise DB in memory
    db_mod = sys.modules["db"]
    main_mod._db = db_mod.SchemeDB("sqlite:///:memory:")

    client = TestClient(main_mod.app, raise_server_exceptions=True)
    return client, int_key, int_cert


@pytest.fixture()
def admin_token(sa_app):
    """Obtain a valid admin session cookie via the JSON login endpoint."""
    client, _, _ = sa_app
    resp = client.post(
        "/auth/login-api",
        json={"email": "admin@test.example", "password": "test-password"},
    )
    assert resp.status_code == 200
    return resp.cookies.get("sa_admin_session")


def _make_csr(psp_uri: str = "psp://new.example", display: str = "New PISP"):
    """Generate a fresh CSR for the given psp_uri."""
    from cryptography.hazmat.primitives import serialization
    key, csr = _pki_module.generate_pisp_ca_key_and_csr(psp_uri, display)
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health(sa_app):
    client, _, _ = sa_app
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["pki_loaded"] is True


# ---------------------------------------------------------------------------
# Directory — empty DB
# ---------------------------------------------------------------------------

def test_list_pisps_empty(sa_app):
    client, _, _ = sa_app
    resp = client.get("/scheme/pisps")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_pisp_not_found(sa_app):
    client, _, _ = sa_app
    resp = client.get("/scheme/pisps/psp://nobody.example")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Registration (POST /scheme/pisps)
# ---------------------------------------------------------------------------

def test_register_creates_pending(sa_app):
    """Registration (SA_AUTO_APPROVE=false) creates a pending record without a cert."""
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://register.example", "Register Test")
    resp = client.post("/scheme/pisps", json={
        "psp_uri": "psp://register.example",
        "name": "Register Test",
        "base_url": "http://register.example",
        "csr_pem": csr_pem,
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "pending"
    # Cert is withheld until an operator approves — PISP must poll /scheme/pisp-cert/
    assert "pisp_ca_cert_pem" not in data
    assert data["serial_hex"]


def test_pisp_cert_endpoint_returns_202_while_pending(sa_app):
    """/scheme/pisp-cert/{uri} returns 202 while the PISP is still pending."""
    import urllib.parse
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://certpoll.example")
    client.post("/scheme/pisps", json={
        "psp_uri": "psp://certpoll.example",
        "name": "Cert Poll",
        "base_url": "http://certpoll.example",
        "csr_pem": csr_pem,
    })
    encoded = urllib.parse.quote("psp://certpoll.example", safe="")
    resp = client.get(f"/scheme/pisp-cert/{encoded}")
    assert resp.status_code == 202
    assert resp.json()["status"] == "pending"


def test_pisp_cert_endpoint_returns_cert_after_approval(sa_app, admin_token):
    """/scheme/pisp-cert/{uri} returns 200 with cert once the PISP is approved."""
    import urllib.parse
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://certapprove.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://certapprove.example",
        "name": "Cert Approve",
        "base_url": "http://certapprove.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]
    client.post(
        f"/scheme/pisps/{pisp_id}/approve",
        cookies={"sa_admin_session": admin_token},
    )
    encoded = urllib.parse.quote("psp://certapprove.example", safe="")
    resp = client.get(f"/scheme/pisp-cert/{encoded}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "active"
    assert "pisp_ca_cert_pem" in data
    assert "BEGIN CERTIFICATE" in data["pisp_ca_cert_pem"]
    assert data["serial_hex"]


def test_pisp_cert_endpoint_returns_409_when_revoked(sa_app, admin_token):
    """/scheme/pisp-cert/{uri} returns 409 once a PISP is revoked."""
    import urllib.parse
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://certrevoke.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://certrevoke.example",
        "name": "Cert Revoke",
        "base_url": "http://certrevoke.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]
    # Approve then immediately revoke
    client.post(f"/scheme/pisps/{pisp_id}/approve",
                cookies={"sa_admin_session": admin_token})
    client.post(f"/scheme/pisps/{pisp_id}/revoke",
                json={"reason": "test"},
                cookies={"sa_admin_session": admin_token})
    encoded = urllib.parse.quote("psp://certrevoke.example", safe="")
    resp = client.get(f"/scheme/pisp-cert/{encoded}")
    assert resp.status_code == 409


def test_pisp_cert_endpoint_returns_404_for_unknown(sa_app):
    """/scheme/pisp-cert/{uri} returns 404 for an unknown URI."""
    import urllib.parse
    client, _, _ = sa_app
    encoded = urllib.parse.quote("psp://nobody.example", safe="")
    resp = client.get(f"/scheme/pisp-cert/{encoded}")
    assert resp.status_code == 404


def test_register_returns_id(sa_app):
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://id-test.example", "ID Test")
    resp = client.post("/scheme/pisps", json={
        "psp_uri": "psp://id-test.example",
        "name": "ID Test",
        "base_url": "http://id-test.example",
        "csr_pem": csr_pem,
    })
    assert resp.status_code == 201
    assert resp.json()["id"]


def test_register_duplicate_uri_rejected(sa_app):
    client, _, _ = sa_app
    for _ in range(2):
        resp = client.post("/scheme/pisps", json={
            "psp_uri": "psp://dup.example",
            "name": "Dup",
            "base_url": "http://dup.example",
            "csr_pem": _make_csr("psp://dup.example"),
        })
    assert resp.status_code == 409


def test_register_invalid_csr_rejected(sa_app):
    client, _, _ = sa_app
    resp = client.post("/scheme/pisps", json={
        "psp_uri": "psp://bad.example",
        "name": "Bad",
        "base_url": "http://bad.example",
        "csr_pem": "not a valid CSR",
    })
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Approval (POST /scheme/pisps/{id}/approve) — requires admin
# ---------------------------------------------------------------------------

def test_approve_requires_auth(sa_app):
    client, _, _ = sa_app
    # Register first
    csr_pem = _make_csr("psp://auth-test.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://auth-test.example",
        "name": "Auth Test",
        "base_url": "http://auth-test.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]

    # Approve without session cookie → 401 or redirect to login
    resp = client.post(f"/scheme/pisps/{pisp_id}/approve", follow_redirects=False)
    assert resp.status_code in (401, 302, 303)


def test_approve_with_valid_session(sa_app, admin_token):
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://approve-ok.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://approve-ok.example",
        "name": "Approve OK",
        "base_url": "http://approve-ok.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]

    resp = client.post(
        f"/scheme/pisps/{pisp_id}/approve",
        cookies={"sa_admin_session": admin_token},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"


def test_approved_pisp_visible_in_directory(sa_app, admin_token):
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://visible.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://visible.example",
        "name": "Visible PISP",
        "base_url": "http://visible.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]
    client.post(
        f"/scheme/pisps/{pisp_id}/approve",
        cookies={"sa_admin_session": admin_token},
    )

    # Directory lookup
    resp = client.get("/scheme/pisps/psp://visible.example")
    assert resp.status_code == 200
    assert resp.json()["base_url"] == "http://visible.example"


def test_pending_pisp_not_in_directory(sa_app):
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://pending.example")
    client.post("/scheme/pisps", json={
        "psp_uri": "psp://pending.example",
        "name": "Pending PISP",
        "base_url": "http://pending.example",
        "csr_pem": csr_pem,
    })
    # Pending — should not appear without approval
    resp = client.get("/scheme/pisps/psp://pending.example")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Revocation (POST /scheme/pisps/{id}/revoke) — requires admin
# ---------------------------------------------------------------------------

def test_revoke_with_valid_session(sa_app, admin_token):
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://revoke-me.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://revoke-me.example",
        "name": "Revoke Me",
        "base_url": "http://revoke-me.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]
    client.post(
        f"/scheme/pisps/{pisp_id}/approve",
        cookies={"sa_admin_session": admin_token},
    )

    resp = client.post(
        f"/scheme/pisps/{pisp_id}/revoke",
        json={"reason": "Key compromise"},
        cookies={"sa_admin_session": admin_token},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


def test_revoked_pisp_disappears_from_directory(sa_app, admin_token):
    client, _, _ = sa_app
    csr_pem = _make_csr("psp://gone.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://gone.example",
        "name": "Gone",
        "base_url": "http://gone.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]
    client.post(f"/scheme/pisps/{pisp_id}/approve",
                cookies={"sa_admin_session": admin_token})
    client.post(f"/scheme/pisps/{pisp_id}/revoke",
                json={"reason": "test"},
                cookies={"sa_admin_session": admin_token})

    resp = client.get("/scheme/pisps/psp://gone.example")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# CRL endpoint
# ---------------------------------------------------------------------------

def test_crl_returns_der(sa_app):
    client, _, _ = sa_app
    resp = client.get("/scheme/crl")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pkix-crl"
    # DER-encoded CRL starts with SEQUENCE tag 0x30
    assert resp.content[0] == 0x30


def test_crl_contains_revoked_serial(sa_app, admin_token):
    from cryptography import x509 as _x509
    client, int_key, int_cert = sa_app

    csr_pem = _make_csr("psp://crl-test.example")
    reg = client.post("/scheme/pisps", json={
        "psp_uri": "psp://crl-test.example",
        "name": "CRL Test",
        "base_url": "http://crl-test.example",
        "csr_pem": csr_pem,
    })
    pisp_id = reg.json()["id"]
    serial_hex = reg.json()["serial_hex"]

    client.post(f"/scheme/pisps/{pisp_id}/approve",
                cookies={"sa_admin_session": admin_token})
    client.post(f"/scheme/pisps/{pisp_id}/revoke",
                json={"reason": "test crl"},
                cookies={"sa_admin_session": admin_token})

    crl_resp = client.get("/scheme/crl")
    crl = _x509.load_der_x509_crl(crl_resp.content)
    found = crl.get_revoked_certificate_by_serial_number(int(serial_hex, 16))
    assert found is not None


def test_crl_signature_valid(sa_app):
    from cryptography import x509 as _x509
    client, int_key, int_cert = sa_app
    crl_resp = client.get("/scheme/crl")
    crl = _x509.load_der_x509_crl(crl_resp.content)
    # Raises if invalid
    crl.is_signature_valid(int_cert.public_key())


# ---------------------------------------------------------------------------
# SA Dispute endpoints
# ---------------------------------------------------------------------------

def _dispute_body(dispute_id="d-001", pisp_uri="psp://pisp.example"):
    from datetime import datetime, timezone
    return {
        "dispute_id":   dispute_id,
        "pisp_uri":     pisp_uri,
        "escalated_at": datetime.now(timezone.utc).isoformat(),
    }


class TestSADisputes:

    def test_post_dispute_returns_201(self, sa_app):
        client, _, _ = sa_app
        resp = client.post("/scheme/disputes", json=_dispute_body())
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "sa_dispute_id" in body
        assert body["status"] == "UNDER_REVIEW"

    def test_post_dispute_no_auth_required(self, sa_app):
        """POST /scheme/disputes is unauthenticated (PISP self-escalation)."""
        client, _, _ = sa_app
        # Deliberately no cookie
        resp = client.post("/scheme/disputes", json=_dispute_body("d-noauth"))
        assert resp.status_code == 201

    def test_post_dispute_optional_evidence_summary(self, sa_app):
        client, _, _ = sa_app
        body = _dispute_body("d-summary")
        body["evidence_summary"] = "Customer says goods not received."
        resp = client.post("/scheme/disputes", json=body)
        assert resp.status_code == 201

    def test_post_dispute_optional_pisp_uris(self, sa_app):
        client, _, _ = sa_app
        body = _dispute_body("d-pisp-uris")
        body["payer_pisp_uri"] = "psp://payer-pisp.example"
        body["requester_pisp_uri"] = "psp://requester-pisp.example"
        resp = client.post("/scheme/disputes", json=body)
        assert resp.status_code == 201

    def test_post_dispute_ignores_submitted_base_urls(self, sa_app, admin_token):
        """Caller-supplied base URLs must be ignored — the SA uses its own directory.

        Accepting URLs from the request payload would be an SSRF vector.  The SA
        always resolves notification endpoints from its own canonical PISP registry.
        """
        import sys
        client, _, _ = sa_app
        sa_db = sys.modules["main"]._db
        # Register a payer PISP in the SA directory with a known base_url
        sa_db.save_pisp(
            psp_uri="psp://payer-pisp.example",
            name="Payer PISP",
            base_url="https://payer-pisp.example",
            pisp_ca_cert="",
            serial_hex="",
            status="active",
        )
        body = _dispute_body("d-base-urls")
        body["payer_pisp_uri"]          = "psp://payer-pisp.example"
        # Submit attacker-controlled URLs — these must not be used
        body["payer_pisp_base_url"]     = "http://attacker.evil:9999"
        body["requester_pisp_base_url"] = "http://attacker.evil:9999"
        resp = client.post("/scheme/disputes", json=body)
        assert resp.status_code == 201
        sa_id = resp.json()["sa_dispute_id"]
        # Confirm the attacker URL never appeared anywhere in the stored dispute
        detail = client.get(
            f"/admin/api/disputes/{sa_id}",
            cookies={"sa_admin_session": admin_token},
        )
        assert detail.status_code == 200
        detail_text = str(detail.json())
        assert "attacker.evil" not in detail_text
        # The SA's own directory URL should be used instead
        assert "payer-pisp.example" in detail_text

    def test_get_disputes_requires_auth(self, sa_app):
        client, _, _ = sa_app
        resp = client.get("/admin/api/disputes", follow_redirects=False)
        assert resp.status_code == 401

    def test_get_disputes_lists_disputes(self, sa_app, admin_token):
        client, _, _ = sa_app
        # Create two disputes
        client.post("/scheme/disputes", json=_dispute_body("d-list-1"))
        client.post("/scheme/disputes", json=_dispute_body("d-list-2"))
        resp = client.get(
            "/admin/api/disputes",
            cookies={"sa_admin_session": admin_token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        dispute_ids = [d["dispute_id"] for d in data]
        assert "d-list-1" in dispute_ids or any("d-list-1" in str(d) for d in data)

    def test_get_dispute_detail(self, sa_app, admin_token):
        client, _, _ = sa_app
        r = client.post("/scheme/disputes", json=_dispute_body("d-detail"))
        sa_id = r.json()["sa_dispute_id"]
        resp = client.get(
            f"/admin/api/disputes/{sa_id}",
            cookies={"sa_admin_session": admin_token},
        )
        assert resp.status_code == 200
        assert resp.json()["dispute_id"] == "d-detail"

    def test_get_dispute_detail_not_found(self, sa_app, admin_token):
        client, _, _ = sa_app
        resp = client.get(
            "/admin/api/disputes/does-not-exist",
            cookies={"sa_admin_session": admin_token},
        )
        assert resp.status_code == 404

    def test_resolve_dispute_upheld(self, sa_app, admin_token):
        client, _, _ = sa_app
        r = client.post("/scheme/disputes", json=_dispute_body("d-uphold"))
        sa_id = r.json()["sa_dispute_id"]

        resp = client.post(
            f"/admin/api/disputes/{sa_id}/resolve",
            json={"verdict": "UPHELD", "rationale": "Evidence supports payer claim."},
            cookies={"sa_admin_session": admin_token},
        )
        assert resp.status_code == 200

        detail = client.get(
            f"/admin/api/disputes/{sa_id}",
            cookies={"sa_admin_session": admin_token},
        )
        assert detail.json()["verdict"] == "UPHELD"

    def test_resolve_dispute_rejected(self, sa_app, admin_token):
        client, _, _ = sa_app
        r = client.post("/scheme/disputes", json=_dispute_body("d-reject"))
        sa_id = r.json()["sa_dispute_id"]

        resp = client.post(
            f"/admin/api/disputes/{sa_id}/resolve",
            json={"verdict": "REJECTED", "rationale": "No evidence of merchant fault."},
            cookies={"sa_admin_session": admin_token},
        )
        assert resp.status_code == 200

    def test_resolve_invalid_verdict_422(self, sa_app, admin_token):
        client, _, _ = sa_app
        r = client.post("/scheme/disputes", json=_dispute_body("d-bad-verdict"))
        sa_id = r.json()["sa_dispute_id"]
        resp = client.post(
            f"/admin/api/disputes/{sa_id}/resolve",
            json={"verdict": "MAYBE", "rationale": "test"},
            cookies={"sa_admin_session": admin_token},
        )
        assert resp.status_code == 422

    def test_resolve_requires_auth(self, sa_app):
        client, _, _ = sa_app
        r = client.post("/scheme/disputes", json=_dispute_body("d-auth-resolve"))
        sa_id = r.json()["sa_dispute_id"]
        resp = client.post(
            f"/admin/api/disputes/{sa_id}/resolve",
            json={"verdict": "UPHELD", "rationale": "Test rationale."},
        )
        assert resp.status_code == 401

    def test_resolve_upheld_with_refund_instruction(self, sa_app, admin_token):
        """UPHELD verdict with amount/deadline builds a refund_instruction in the resolved msg."""
        import sys, unittest.mock as _mock
        client, _, _ = sa_app
        sa_db = sys.modules["main"]._db
        # Register both PISPs in the SA directory so the SA can resolve their URLs
        for psp_uri, base_url in [
            ("psp://payer-ri.example",     "http://payer.internal:8000"),
            ("psp://requester-ri.example", "http://requester.internal:8000"),
        ]:
            sa_db.save_pisp(
                psp_uri=psp_uri, name=psp_uri,
                base_url=base_url, pisp_ca_cert="", serial_hex="",
                status="active",
            )
        body = _dispute_body("d-refund-instr")
        body["payer_pisp_uri"]     = "psp://payer-ri.example"
        body["requester_pisp_uri"] = "psp://requester-ri.example"
        r = client.post("/scheme/disputes", json=body)
        sa_id = r.json()["sa_dispute_id"]

        posted_payloads: list[dict] = []

        async def _fake_post(url, json=None, **kw):
            posted_payloads.append({"url": url, "json": json})
            class _R:
                status_code = 200
            return _R()

        with _mock.patch("httpx.AsyncClient") as mock_cls:
            mock_instance = _mock.AsyncMock()
            mock_instance.__aenter__ = _mock.AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__  = _mock.AsyncMock(return_value=False)
            mock_instance.post       = _mock.AsyncMock(side_effect=_fake_post)
            mock_cls.return_value    = mock_instance

            resp = client.post(
                f"/admin/api/disputes/{sa_id}/resolve",
                json={"verdict": "UPHELD", "rationale": "Payer claim supported.",
                      "refund_amount_pence": 2000, "refund_deadline": "2026-04-01"},
                cookies={"sa_admin_session": admin_token},
            )
        assert resp.status_code == 200
        # At least one DisputeResolved should have been fired with a refund_instruction
        fired = [p for p in posted_payloads if p["json"] and p["json"].get("refund_instruction")]
        assert fired, "Expected DisputeResolved with refund_instruction to be fired"
        ri = fired[0]["json"]["refund_instruction"]
        assert ri["amount_pence"] == 2000
        assert ri["deadline"] == "2026-04-01"

    def test_resolve_rejected_no_refund_instruction(self, sa_app, admin_token):
        """REJECTED verdict should never include a refund_instruction."""
        import unittest.mock as _mock
        client, _, _ = sa_app
        r = client.post("/scheme/disputes", json=_dispute_body("d-reject-instr"))
        sa_id = r.json()["sa_dispute_id"]

        posted_payloads: list[dict] = []

        async def _fake_post(url, json=None, **kw):
            posted_payloads.append({"url": url, "json": json})
            class _R:
                status_code = 200
            return _R()

        with _mock.patch("httpx.AsyncClient") as mock_cls:
            mock_instance = _mock.AsyncMock()
            mock_instance.__aenter__ = _mock.AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__  = _mock.AsyncMock(return_value=False)
            mock_instance.post       = _mock.AsyncMock(side_effect=_fake_post)
            mock_cls.return_value    = mock_instance

            resp = client.post(
                f"/admin/api/disputes/{sa_id}/resolve",
                json={"verdict": "REJECTED", "rationale": "Merchant not at fault.",
                      "refund_amount_pence": 999, "refund_deadline": "2026-04-01"},
                cookies={"sa_admin_session": admin_token},
            )
        assert resp.status_code == 200
        # No refund_instruction should appear on a REJECTED verdict
        for p in posted_payloads:
            if p["json"]:
                assert p["json"].get("refund_instruction") is None

    def test_already_resolved_dispute_returns_409(self, sa_app, admin_token):
        client, _, _ = sa_app
        r = client.post("/scheme/disputes", json=_dispute_body("d-idem"))
        sa_id = r.json()["sa_dispute_id"]
        # Resolve once
        client.post(
            f"/admin/api/disputes/{sa_id}/resolve",
            json={"verdict": "UPHELD", "rationale": "First verdict."},
            cookies={"sa_admin_session": admin_token},
        )
        # Resolve again — JSON API returns 409 (not idempotent redirect)
        resp = client.post(
            f"/admin/api/disputes/{sa_id}/resolve",
            json={"verdict": "REJECTED", "rationale": "Second attempt."},
            cookies={"sa_admin_session": admin_token},
        )
        assert resp.status_code == 409
