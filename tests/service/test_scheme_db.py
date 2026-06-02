"""
Tests for scheme-authority/db.py — SchemeDB CRUD and seed import.

Covers:
  - save_pisp / get_pisp_by_id / get_pisp_by_uri / list_pisps
  - approve_pisp / revoke_pisp (status transitions + CRL sequence increment)
  - list_revoked
  - seed_from_file (imports JSON seed; skips when DB already populated)
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
from datetime import datetime, timezone

import pytest

ROOT = pathlib.Path(__file__).parent.parent.parent  # SA repo root
sys.path.insert(0, str(ROOT))

import importlib

_db_spec = importlib.util.spec_from_file_location("sa_db", ROOT / "db.py")
sa_db = importlib.util.module_from_spec(_db_spec)
_db_spec.loader.exec_module(sa_db)
SchemeDB = sa_db.SchemeDB

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    """In-memory SchemeDB instance (SQLite)."""
    db = SchemeDB("sqlite:///:memory:")
    return db


SAMPLE_PEM = """\
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
-----END CERTIFICATE-----
"""


def _save(db: SchemeDB, *, psp_uri="psp://test.example", serial="aabbcc",
          status="pending") -> dict:
    return db.save_pisp(
        psp_uri=psp_uri,
        name="Test PISP",
        base_url="http://test.example",
        pisp_ca_cert=SAMPLE_PEM,
        serial_hex=serial,
        status=status,
    )


# ---------------------------------------------------------------------------
# save / get
# ---------------------------------------------------------------------------

def test_save_and_get_by_id(db):
    rec = _save(db)
    assert rec["id"]
    assert rec["psp_uri"] == "psp://test.example"
    assert rec["status"] == "pending"

    fetched = db.get_pisp_by_id(rec["id"])
    assert fetched is not None
    assert fetched["psp_uri"] == "psp://test.example"
    assert fetched["name"] == "Test PISP"


def test_get_by_uri(db):
    _save(db)
    found = db.get_pisp_by_uri("psp://test.example")
    assert found is not None
    assert found["base_url"] == "http://test.example"


def test_get_missing_returns_none(db):
    assert db.get_pisp_by_id("nonexistent-id") is None
    assert db.get_pisp_by_uri("psp://nobody.example") is None


def test_save_records_registered_at(db):
    rec = _save(db)
    # registered_at must be a valid ISO timestamp
    ts = datetime.fromisoformat(rec["registered_at"])
    now = datetime.now(timezone.utc)
    # recorded within the last 5 seconds
    delta = abs((now.replace(tzinfo=None) - ts.replace(tzinfo=None)).total_seconds())
    assert delta < 5


# ---------------------------------------------------------------------------
# list_pisps
# ---------------------------------------------------------------------------

def test_list_all(db):
    _save(db, psp_uri="psp://a.example", status="active")
    _save(db, psp_uri="psp://b.example", status="pending")
    _save(db, psp_uri="psp://c.example", status="revoked")

    all_pisps = db.list_pisps()
    assert len(all_pisps) == 3


def test_list_filtered_by_status(db):
    _save(db, psp_uri="psp://a.example", status="active")
    _save(db, psp_uri="psp://b.example", status="pending")
    _save(db, psp_uri="psp://c.example", status="revoked")

    assert len(db.list_pisps(status="active")) == 1
    assert len(db.list_pisps(status="pending")) == 1
    assert len(db.list_pisps(status="revoked")) == 1
    assert len(db.list_pisps(status="active")) == 1


# ---------------------------------------------------------------------------
# approve / revoke transitions
# ---------------------------------------------------------------------------

def test_approve_pending(db):
    rec = _save(db, status="pending")
    db.approve_pisp(rec["id"])
    updated = db.get_pisp_by_id(rec["id"])
    assert updated["status"] == "active"
    assert updated["approved_at"] is not None


def test_revoke_active(db):
    rec = _save(db, status="active")
    seq_before = db.get_crl_sequence()
    db.revoke_pisp(rec["id"], reason="Key compromise")
    updated = db.get_pisp_by_id(rec["id"])
    assert updated["status"] == "revoked"
    assert updated["revoke_reason"] == "Key compromise"
    assert updated["revoked_at"] is not None
    # CRL sequence must have incremented
    assert db.get_crl_sequence() == seq_before + 1


def test_revoke_increments_crl_sequence_each_time(db):
    a = _save(db, psp_uri="psp://a.example", serial="aa", status="active")
    b = _save(db, psp_uri="psp://b.example", serial="bb", status="active")
    seq0 = db.get_crl_sequence()

    db.revoke_pisp(a["id"], reason="")
    assert db.get_crl_sequence() == seq0 + 1

    db.revoke_pisp(b["id"], reason="")
    assert db.get_crl_sequence() == seq0 + 2


# ---------------------------------------------------------------------------
# list_revoked
# ---------------------------------------------------------------------------

def test_list_revoked_empty(db):
    _save(db, status="active")
    assert db.list_revoked() == []


def test_list_revoked_contains_revoked_entries(db):
    a = _save(db, psp_uri="psp://a.example", serial="deadbeef01", status="active")
    b = _save(db, psp_uri="psp://b.example", serial="deadbeef02", status="active")
    _save(db, psp_uri="psp://c.example", serial="deadbeef03", status="active")

    db.revoke_pisp(a["id"], reason="Test revocation A")
    db.revoke_pisp(b["id"], reason="Test revocation B")

    revoked = db.list_revoked()
    assert len(revoked) == 2
    serials = {r["serial_hex"] for r in revoked}
    assert "deadbeef01" in serials
    assert "deadbeef02" in serials


# ---------------------------------------------------------------------------
# seed_from_file
# ---------------------------------------------------------------------------

def test_seed_imports_records(db, tmp_path):
    seed = [
        {
            "psp_uri":      "psp://pisp.openpisp.local",
            "name":         "OpenPISP Primary",
            "base_url":     "http://pisp.openpisp.local",
            "pisp_ca_cert": SAMPLE_PEM,
            "serial_hex":   "cafebabe01",
        },
        {
            "psp_uri":      "psp://pisp-peer.openpisp.local",
            "name":         "OpenPISP Peer",
            "base_url":     "http://pisp-peer.openpisp.local",
            "pisp_ca_cert": SAMPLE_PEM,
            "serial_hex":   "cafebabe02",
        },
    ]
    seed_file = tmp_path / "sa_seed.json"
    seed_file.write_text(json.dumps(seed))

    n = db.seed_from_file(str(seed_file))
    assert n == 2

    all_pisps = db.list_pisps()
    assert len(all_pisps) == 2
    uris = {p["psp_uri"] for p in all_pisps}
    assert "psp://pisp.openpisp.local" in uris
    assert all(p["status"] == "active" for p in all_pisps)


def test_seed_skips_when_already_populated(db, tmp_path):
    # Pre-populate
    _save(db, psp_uri="psp://existing.example")

    seed = [{"psp_uri": "psp://new.example", "name": "New", "base_url": "http://new",
              "pisp_ca_cert": SAMPLE_PEM, "serial_hex": "ff"}]
    seed_file = tmp_path / "sa_seed.json"
    seed_file.write_text(json.dumps(seed))

    n = db.seed_from_file(str(seed_file))
    assert n == 0   # skipped because DB was not empty
    assert len(db.list_pisps()) == 1   # only the pre-existing record
