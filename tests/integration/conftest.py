"""
Session-scoped testcontainers fixtures for Protocol E integration tests.

Spins up real Docker containers (SA + PISP) for each test session, then tears
them down.  Tests hit the containers over HTTP using dynamically assigned host
ports; containers talk to each other via a private Docker network using
service aliases.

Required images (built from the RI repo root):
    psp-scheme-authority   docker build -t psp-scheme-authority scheme-authority
    psp-pisp               docker build -t psp-pisp -f pisp/Dockerfile .
    python:3.12-slim       pulled from Docker Hub (attacker cert server)

Override images via environment variables:
    SA_IMAGE   (default: psp-scheme-authority)
    PISP_IMAGE (default: psp-pisp)

Mark: pytest.mark.integration_containers
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Generator

import httpx
import pytest

# ---------------------------------------------------------------------------
# pki/pki.py — this conftest lives inside the SA repo/submodule, so pki/ is
# two levels up (scheme-authority/pki/ relative to scheme-authority/tests/integration/)
# ---------------------------------------------------------------------------
_SA_ROOT = Path(__file__).parent.parent.parent  # scheme-authority/ repo root
_PKI_DIR = _SA_ROOT / "pki"
if str(_PKI_DIR) not in sys.path:
    sys.path.insert(0, str(_PKI_DIR))
import pki as pki_lib  # noqa: E402  (after sys.path manipulation)

# ---------------------------------------------------------------------------
# Image names — override via env to point at ECR images in CI
# ---------------------------------------------------------------------------
SA_IMAGE   = os.getenv("SA_IMAGE",   "psp-scheme-authority")
PISP_IMAGE = os.getenv("PISP_IMAGE", "psp-pisp")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pem(obj) -> str:
    """Serialize a cryptography key or cert to PEM string."""
    from cryptography.hazmat.primitives import serialization
    if hasattr(obj, "private_bytes"):
        return obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    return obj.public_bytes(serialization.Encoding.PEM).decode()


def _wait_http(url: str, *, timeout: int = 60, interval: float = 1.0) -> None:
    """Poll GET ``url`` until it returns 200 or timeout expires."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code == 200:
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(interval)
    raise TimeoutError(
        f"Service at {url!r} did not become healthy within {timeout}s "
        f"(last error: {last_exc})"
    )


def _wait_pisp_registered(sa_url: str, pisp_uri: str, *, timeout: int = 30) -> None:
    """Poll the SA directory until ``pisp_uri`` appears as active.

    GET /scheme/pisps/{uri} returns 200 only for active PISPs (404 otherwise),
    so a 200 response is sufficient to confirm the PISP is active.
    """
    import urllib.parse
    encoded = urllib.parse.quote(pisp_uri, safe="")
    endpoint = f"{sa_url}/scheme/pisps/{encoded}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(endpoint, timeout=3.0)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(1.0)
    raise TimeoutError(
        f"PISP {pisp_uri!r} did not appear as active in SA within {timeout}s"
    )


# ---------------------------------------------------------------------------
# Session-scoped PKI hierarchy
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def scheme_pki():
    """
    Generate a complete Scheme PKI hierarchy (Root → Intermediate) once per
    session.  The Intermediate key/cert are injected into the SA container;
    all PISP certs in the session are signed by the same Intermediate CA,
    which is what the running PISP trusts.
    """
    root_key,  root_cert = pki_lib.generate_root_ca(lifetime_days=1)
    int_key,   int_cert  = pki_lib.generate_intermediate_ca(
        root_key, root_cert, lifetime_days=1
    )
    return {
        "root_key":  root_key,
        "root_cert": root_cert,
        "int_key":   int_key,
        "int_cert":  int_cert,
    }


# ---------------------------------------------------------------------------
# Docker network shared by all containers in the session
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def docker_network():
    """Isolated Docker bridge network for the test session."""
    from testcontainers.core.network import Network
    with Network() as net:
        yield net


# ---------------------------------------------------------------------------
# Scheme Authority container
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sa_container(scheme_pki, docker_network, tmp_path_factory):
    """
    Scheme Authority container with pre-loaded PKI.

    SA_AUTO_APPROVE=true so PISP containers self-register without manual
    operator approval.  PKI is passed as PEM env vars so no volume mounts
    are needed for the SA.
    """
    from testcontainers.core.container import DockerContainer

    sa = (
        DockerContainer(SA_IMAGE)
        .with_network(docker_network)
        .with_network_aliases("scheme-authority")
        .with_exposed_ports(8000)
        .with_env("SA_DB_URL",            "sqlite:////tmp/sa_test.db")
        .with_env("SA_BASE_URL",          "http://scheme-authority:8000")
        .with_env("SA_AUTO_APPROVE",       "true")
        .with_env("PSP_E_SIGNING_ENABLED", "true")
        .with_env("INTERMEDIATE_CA_KEY",  _pem(scheme_pki["int_key"]))
        .with_env("INTERMEDIATE_CA_CERT", _pem(scheme_pki["int_cert"]))
        .with_env("ROOT_CA_CERT",         _pem(scheme_pki["root_cert"]))
        .with_env("BUILD_COMMIT",         "integration-test")
    )

    with sa:
        host_port = sa.get_exposed_port(8000)
        host      = sa.get_container_host_ip()
        sa_url    = f"http://{host}:{host_port}"

        _wait_http(f"{sa_url}/health", timeout=30)

        # Expose the host-accessible URL as an attribute for tests
        sa._test_url = sa_url  # type: ignore[attr-defined]
        yield sa


# ---------------------------------------------------------------------------
# PISP container  (self-registers with the SA on startup)
# ---------------------------------------------------------------------------

PISP_URI = "psp://test-pisp.integration.local"

@pytest.fixture(scope="session")
def pisp_container(sa_container, docker_network, tmp_path_factory):
    """
    PISP container with PSP_SIGNING_ENABLED=true.

    On startup the PISP:
      1. Generates a fresh EC CA key in the mounted /data volume.
      2. Fetches the CA chain (intermediate + root) from the SA.
      3. Submits a CSR to the SA and receives a signed PISP CA cert (auto-approved).
      4. Builds PocPki.from_files() and starts serving .well-known/psp-certs.json.

    This exercises the full registration flow and gives us a running PISP with
    a cert chain that the SA trusts.
    """
    from testcontainers.core.container import DockerContainer

    pki_data = tmp_path_factory.mktemp("pisp_pki")

    pisp = (
        DockerContainer(PISP_IMAGE)
        .with_network(docker_network)
        .with_network_aliases("pisp")
        .with_exposed_ports(8000)
        .with_env("PISP_URI",              PISP_URI)
        .with_env("PISP_ROLE",             "standard")
        .with_env("BASE_URL",              "http://pisp:8000")
        .with_env("PSP_SIGNING_ENABLED",   "true")
        .with_env("SCHEME_AUTHORITY_URL",  "http://scheme-authority:8000")
        .with_env("PSP_CA_KEY_FILE",       "/data/pisp-ca.key.pem")
        .with_env("PSP_CA_CERT_FILE",      "/data/pisp-ca.cert.pem")
        .with_env("BUILD_COMMIT",          "integration-test")
        .with_volume_mapping(str(pki_data), "/data", "rw")
    )

    with pisp:
        host_port = pisp.get_exposed_port(8000)
        host      = pisp.get_container_host_ip()
        pisp_url  = f"http://{host}:{host_port}"

        # PISP startup includes SA registration — give it more time
        _wait_http(f"{pisp_url}/health", timeout=60)
        _wait_pisp_registered(sa_container._test_url, PISP_URI, timeout=30)

        pisp._test_url = pisp_url  # type: ignore[attr-defined]
        yield pisp


# ---------------------------------------------------------------------------
# Attacker PISP fixtures  (used by E_SEC_002 — wrong-issuer test)
# ---------------------------------------------------------------------------

ATTACKER_URI = "psp://attacker-pisp.integration.local"


@pytest.fixture(scope="session")
def attacker_pki(scheme_pki):
    """
    Generate an attacker PISP CA key/cert signed by the SAME Scheme Intermediate
    CA as the real PISP.  This means the cert chain validates successfully — the
    signature itself is cryptographically valid.  What makes the attacker's
    message *illegitimate* is that its URI is not the SA's URI.

    This fixture drives E_SEC_002: the PISP should verify the signature (it's
    valid) and then reject on the issuer check (iss != SA URI).
    """
    int_key   = scheme_pki["int_key"]
    int_cert  = scheme_pki["int_cert"]
    root_cert = scheme_pki["root_cert"]

    # Generate attacker PISP CA (CSR → signed by our Intermediate CA)
    ca_key, csr = pki_lib.generate_pisp_ca_key_and_csr(ATTACKER_URI, "Attacker PISP")
    ca_cert      = pki_lib.sign_pisp_csr(csr, int_key, int_cert)

    # Issue a short-lived leaf cert
    leaf_key, leaf_cert = pki_lib.issue_leaf_cert(ca_key, ca_cert, kid="attacker-leaf-0")

    psp_certs = pki_lib.build_psp_certs_json(
        "attacker-leaf-0",
        leaf_cert,
        ca_cert,
        int_cert,
        root_cert,
    )

    return {
        "ca_key":    ca_key,
        "ca_cert":   ca_cert,
        "leaf_key":  leaf_key,
        "leaf_cert": leaf_cert,
        "kid":       "attacker-leaf-0",
        "uri":       ATTACKER_URI,
        "psp_certs": psp_certs,
    }


@pytest.fixture(scope="session")
def attacker_cert_server(attacker_pki, docker_network, sa_container):
    """
    Minimal HTTP server container that serves the attacker's .well-known/psp-certs.json
    on the Docker network so the PISP container can fetch the attacker cert chain.

    Registers the attacker PISP in the SA directory with
    base_url=http://attacker-pisp:8080.  With SA_AUTO_APPROVE=true the registration
    is immediately active — so resolve_pisp() will find it and fetch from our server.

    Returns the attacker_pki dict (passed through for convenience).
    """
    from testcontainers.core.container import DockerContainer

    # Encode psp-certs.json as base64 and pass it as an env var so the container
    # writes the file itself at startup — no volume mount needed.  Volume mounts
    # from macOS temp directories (/var/folders/…) are invisible inside Colima's
    # Linux VM; this approach works on any Docker host.
    psp_certs_b64 = base64.b64encode(
        json.dumps(attacker_pki["psp_certs"]).encode()
    ).decode()

    server = (
        DockerContainer("python:3.12-slim")
        .with_network(docker_network)
        .with_network_aliases("attacker-pisp")
        .with_exposed_ports(8080)
        .with_env("PSP_CERTS_B64", psp_certs_b64)
        .with_command(["sh", "-c",
            "mkdir -p /serve/.well-known && "
            "echo $PSP_CERTS_B64 | base64 -d > /serve/.well-known/psp-certs.json && "
            "python3 -m http.server 8080 --directory /serve"
        ])
    )

    with server:
        host_port = server.get_exposed_port(8080)
        host      = server.get_container_host_ip()
        server_url = f"http://{host}:{host_port}"

        # Wait for the HTTP server to be ready
        _wait_http(f"{server_url}/.well-known/psp-certs.json", timeout=20)

        # Register the attacker PISP in the SA directory so resolve_pisp() works.
        # The CSR is the attacker's real CA cert (already signed — we submit the
        # cert PEM directly).  SA only requires a valid CSR for new registrations;
        # since SA_AUTO_APPROVE=true and we have the actual CA key, we generate a
        # fresh CSR from the attacker's CA key.
        csr    = pki_lib.generate_pisp_csr_from_key(
            attacker_pki["ca_key"], ATTACKER_URI, "Attacker PISP"
        )
        from cryptography.hazmat.primitives import serialization as _ser
        csr_pem = csr.public_bytes(_ser.Encoding.PEM).decode()

        reg = httpx.post(
            f"{sa_container._test_url}/scheme/pisps",
            json={
                "psp_uri":  ATTACKER_URI,
                "name":     "Attacker PISP (integration test)",
                "base_url": "http://attacker-pisp:8080",  # Docker-internal URL
                "csr_pem":  csr_pem,
            },
            timeout=10.0,
        )
        # 201 = newly registered+approved (SA_AUTO_APPROVE=true)
        # 409 = already registered from a previous run (still fine)
        assert reg.status_code in (201, 409), (
            f"Attacker PISP registration failed: {reg.status_code} {reg.text}"
        )

        server._test_url = server_url  # type: ignore[attr-defined]
        yield attacker_pki
