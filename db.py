"""
Scheme Authority — SQLite persistence layer.

Follows the same SQLAlchemy Core + text() pattern as pisp/ledger_db.py.
No-op mode when SA_DB_URL is not set (used in tests with in-memory SQLite).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import StaticPool
    _SA_AVAILABLE = True
except ImportError:          # pragma: no cover
    _SA_AVAILABLE = False    # type: ignore[assignment]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Settlement window helpers — pure functions, no DB access
# ---------------------------------------------------------------------------

def window_phases(year: int, month: int) -> dict:
    """Compute all phase timestamps for a settlement window (all UTC ISO-8601).

    All timing is derived deterministically from the year/month and the
    SA config knobs.  No row needs to be written; any PISP can call this
    to discover the schedule for any past or future window.

    Phases:
      transaction_period  — the calendar month itself
      reporting           — PISPs submit aggregate reports
      reconciling         — SA flags discrepancies; PISPs may resubmit
      awaiting_payment    — net debtor PISPs pay into SA account
      paying_out          — SA distributes to net creditors
      complete            — all done
    """
    import calendar as _cal
    from datetime import timedelta as _td
    try:
        import config as _cfg
    except ImportError:
        # Fallback defaults when running outside SA container (e.g. tests)
        class _cfg:  # type: ignore[no-redef]
            SETTLEMENT_REPORTING_DAYS  = 7
            SETTLEMENT_RECONCILE_DAYS  = 3
            SETTLEMENT_PAYMENT_DAYS    = 7
            SETTLEMENT_PAYOUT_DAYS     = 7

    last_day = _cal.monthrange(year, month)[1]
    period_start        = datetime(year, month,    1,        0,  0,  0, tzinfo=timezone.utc)
    period_end          = datetime(year, month, last_day,   23, 59, 59, tzinfo=timezone.utc)
    reporting_opens     = period_end          + _td(seconds=1)
    reporting_closes    = reporting_opens     + _td(days=_cfg.SETTLEMENT_REPORTING_DAYS)
    reconcile_closes    = reporting_closes    + _td(days=_cfg.SETTLEMENT_RECONCILE_DAYS)
    payment_due         = reconcile_closes    + _td(days=_cfg.SETTLEMENT_PAYMENT_DAYS)
    settlement_due      = payment_due         + _td(days=_cfg.SETTLEMENT_PAYOUT_DAYS)

    return {
        "window_id":                  f"{year:04d}-{month:02d}",
        "year":                       year,
        "month":                      month,
        "transaction_period_start":   period_start.isoformat(),
        "transaction_period_end":     period_end.isoformat(),
        "reporting_opens_at":         reporting_opens.isoformat(),
        "reporting_closes_at":        reporting_closes.isoformat(),
        "reconciliation_closes_at":   reconcile_closes.isoformat(),
        "payment_due_by":             payment_due.isoformat(),
        "settlement_due_by":          settlement_due.isoformat(),
    }


# ---------------------------------------------------------------------------
# Dev-only phase overrides — populated via POST /admin/api/dev/windows/{id}/force-status
# (only when SA_AUTO_APPROVE=true).  Cleared on container restart.  Never used in prod.
# ---------------------------------------------------------------------------
_window_status_overrides: dict[str, str] = {}


def window_status(phases: dict) -> str:
    """Derive the current lifecycle phase of a window from UTC now.

    Checks _window_status_overrides first — allows dev deployments to
    fast-forward a window into a target phase without waiting for real time
    to pass.
    """
    override = _window_status_overrides.get(phases["window_id"])
    if override:
        return override
    now = datetime.now(timezone.utc).isoformat()
    if now < phases["reporting_opens_at"]:
        return "transaction_period"
    if now < phases["reporting_closes_at"]:
        return "reporting"
    if now < phases["reconciliation_closes_at"]:
        return "reconciling"
    if now < phases["payment_due_by"]:
        return "awaiting_payment"
    if now < phases["settlement_due_by"]:
        return "paying_out"
    return "complete"


def recent_windows(n: int = 6) -> list[dict]:
    """Return phases for the last n calendar months (most recent first)."""
    from datetime import timedelta as _td
    results = []
    # Start from the current month and walk backwards
    now = datetime.now(timezone.utc)
    year, month = now.year, now.month
    for _ in range(n):
        phases = window_phases(year, month)
        phases["status"] = window_status(phases)
        results.append(phases)
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return results


def calculate_scheme_fee(amount_pence: int, rate: float, cap_pence: int) -> int:
    """Return the scheme fee for a transaction.

    fee = min(floor(amount_pence × rate), cap_pence)

    Uses floor (int truncation) for determinism — both the PISP and the SA
    must agree on the fee without floating-point rounding differences.
    """
    return min(int(amount_pence * rate), cap_pence)


class SchemeDB:
    """Persistence layer for the Scheme Authority.

    Tables
    ------
    pisps                  — registered PISP records (status: pending / active / revoked / suspended)
    crl_sequence           — monotonically increasing CRL number (RFC 5280 §5.2.3)
    sa_disputes            — disputes escalated to SA arbitration
    fee_schedules          — per-transaction fee rules (O7); per-PISP with global default
    compliance_reports     — individual settled transactions reported by PISPs (S5)
    pisp_window_reports    — one aggregate report per PISP per window (S5)
    settlement_obligations — net obligations derived from reports (X4 / X8)
    settlement_obligations — net position per PISP per window (X8)
    """

    def __init__(self, db_url: Optional[str] = None) -> None:
        self._engine = None
        if not db_url or not _SA_AVAILABLE:
            return
        if db_url == "sqlite:///:memory:":
            # In-memory SQLite: use StaticPool so all connections share the same
            # underlying connection.  Without this, each SQLAlchemy connection sees
            # a fresh empty database, causing "no such table" errors.
            self._engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                future=True,
            )
        else:
            self._engine = create_engine(db_url, future=True)
        self._create_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_tables(self) -> None:
        with self._engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS pisps (
                    id            TEXT PRIMARY KEY,
                    psp_uri       TEXT UNIQUE NOT NULL,
                    name          TEXT NOT NULL,
                    base_url      TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    pisp_ca_cert  TEXT NOT NULL,
                    serial_hex    TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    approved_at   TEXT,
                    revoked_at    TEXT,
                    revoke_reason TEXT
                )
            """))
        # b_url column — added in T09 (Inter-PISP Protocol dedicated mTLS endpoint).
        # suspended_at / suspend_reason — added in S11 (emergency suspension).
        # settlement_* columns — added in X8 (dogfooding settlement payments).
        # ALTER TABLE is idempotent-safe: ignore the error if already present.
        with self._engine.begin() as conn:
            for _col in (
                "b_url TEXT",
                "suspended_at TEXT",
                "suspend_reason TEXT",
                "settlement_sort_code TEXT",
                "settlement_account_number TEXT",
                "settlement_account_name TEXT",
            ):
                try:
                    conn.execute(text(f"ALTER TABLE pisps ADD COLUMN {_col}"))
                except Exception:
                    pass  # column already exists
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS crl_sequence (
                    id  INTEGER PRIMARY KEY CHECK (id = 1),
                    seq INTEGER NOT NULL DEFAULT 0
                )
            """))
            # Ensure the single CRL sequence row exists
            conn.execute(text(
                "INSERT OR IGNORE INTO crl_sequence (id, seq) VALUES (1, 0)"
            ))

    # ------------------------------------------------------------------
    # PISP management
    # ------------------------------------------------------------------

    def save_pisp(
        self,
        psp_uri: str,
        name: str,
        base_url: str,
        pisp_ca_cert: str,
        serial_hex: str,
        status: str = "pending",
        b_url: Optional[str] = None,
    ) -> dict:
        """Insert a new PISP record. Returns the full row dict."""
        pisp_id = str(uuid.uuid4())
        now = _utcnow()
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO pisps
                        (id, psp_uri, name, base_url, b_url, status,
                         pisp_ca_cert, serial_hex, registered_at)
                    VALUES
                        (:id, :psp_uri, :name, :base_url, :b_url, :status,
                         :pisp_ca_cert, :serial_hex, :registered_at)
                """), {
                    "id": pisp_id, "psp_uri": psp_uri, "name": name,
                    "base_url": base_url, "b_url": b_url, "status": status,
                    "pisp_ca_cert": pisp_ca_cert, "serial_hex": serial_hex,
                    "registered_at": now,
                })
        return {
            "id": pisp_id, "psp_uri": psp_uri, "name": name,
            "base_url": base_url, "b_url": b_url, "status": status,
            "pisp_ca_cert": pisp_ca_cert, "serial_hex": serial_hex,
            "registered_at": now, "approved_at": None,
            "revoked_at": None, "revoke_reason": None,
        }

    def update_pisp(
        self,
        pisp_id: str,
        base_url: str | None = None,
        b_url: str | None = None,
        name: str | None = None,
    ) -> None:
        if not self._engine:
            return
        updates = {}
        if base_url is not None:
            updates["base_url"] = base_url
        if b_url is not None:
            updates["b_url"] = b_url
        if name is not None:
            updates["name"] = name
        if not updates:
            return
        set_clause = ", ".join(f"{k}=:{k}" for k in updates)
        updates["id"] = pisp_id
        with self._engine.begin() as conn:
            conn.execute(text(f"UPDATE pisps SET {set_clause} WHERE id=:id"), updates)

    def approve_pisp(self, pisp_id: str) -> None:
        now = _utcnow()
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    UPDATE pisps SET status='active', approved_at=:now
                    WHERE id=:id
                """), {"id": pisp_id, "now": now})

    def revoke_pisp(self, pisp_id: str, reason: str = "") -> None:
        now = _utcnow()
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    UPDATE pisps
                    SET status='revoked', revoked_at=:now, revoke_reason=:reason
                    WHERE id=:id
                """), {"id": pisp_id, "now": now, "reason": reason})
                # Increment CRL sequence on every revoke action (RFC 5280 §5.2.3)
                conn.execute(text(
                    "UPDATE crl_sequence SET seq = seq + 1 WHERE id = 1"
                ))

    def suspend_pisp(self, pisp_id: str, reason: str = "") -> None:
        """S11 — suspend a PISP immediately without cert revocation.

        Suspended PISPs are excluded from the public directory (peers can no
        longer discover them) but their cert is NOT added to the CRL.  This
        makes suspension instantly effective and reversible, unlike revocation
        which is permanent and propagates via CRL.
        """
        now = _utcnow()
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    UPDATE pisps
                    SET status='suspended', suspended_at=:now, suspend_reason=:reason
                    WHERE id=:id
                """), {"id": pisp_id, "now": now, "reason": reason})

    def unsuspend_pisp(self, pisp_id: str) -> None:
        """S11 — lift a suspension and restore the PISP to active status."""
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    UPDATE pisps
                    SET status='active', suspended_at=NULL, suspend_reason=NULL
                    WHERE id=:id AND status='suspended'
                """), {"id": pisp_id})

    def get_pisp_by_id(self, pisp_id: str) -> Optional[dict]:
        if not self._engine:
            return None
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM pisps WHERE id=:id"),
                {"id": pisp_id},
            ).mappings().first()
        return dict(row) if row else None

    def get_pisp_by_uri(self, psp_uri: str) -> Optional[dict]:
        if not self._engine:
            return None
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM pisps WHERE psp_uri=:uri"),
                {"uri": psp_uri},
            ).mappings().first()
        return dict(row) if row else None

    def list_pisps(self, status: Optional[str] = None) -> list[dict]:
        if not self._engine:
            return []
        q = "SELECT * FROM pisps"
        params: dict = {}
        if status:
            q += " WHERE status=:status"
            params["status"] = status
        q += " ORDER BY registered_at DESC"
        with self._engine.connect() as conn:
            rows = conn.execute(text(q), params).mappings().all()
        return [dict(r) for r in rows]

    def list_revoked(self) -> list[dict]:
        """Return [{serial_hex, revoked_at}] for all revoked PISPs."""
        if not self._engine:
            return []
        with self._engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT serial_hex, revoked_at FROM pisps WHERE status='revoked'"
            )).mappings().all()
        return [dict(r) for r in rows]

    def get_crl_sequence(self) -> int:
        if not self._engine:
            return 0
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT seq FROM crl_sequence WHERE id=1")
            ).first()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Seed support — import pre-generated PISP records at first startup
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # SA Disputes
    # ------------------------------------------------------------------

    def _ensure_sa_disputes_table(self) -> None:
        """Create sa_disputes table if it does not exist, and apply column migrations.

        Called lazily so existing SchemeDB instances automatically gain new
        columns on next use.  ALTER TABLE ADD COLUMN is idempotent via
        try/except (SQLite raises OperationalError on duplicate columns).
        """
        if not self._engine:
            return
        with self._engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS sa_disputes (
                    sa_dispute_id        TEXT PRIMARY KEY,
                    dispute_id           TEXT NOT NULL,
                    pisp_uri             TEXT NOT NULL,
                    escalated_at         TEXT NOT NULL,
                    status               TEXT NOT NULL DEFAULT 'UNDER_REVIEW',
                    evidence_summary     TEXT,
                    verdict              TEXT,
                    resolved_at          TEXT,
                    resolved_by          TEXT,
                    payer_pisp_uri       TEXT,
                    requester_pisp_uri   TEXT,
                    payer_pisp_base_url      TEXT,
                    requester_pisp_base_url  TEXT
                )
            """))
            # Column migrations for DBs created before these columns were added.
            for _col in ("payer_pisp_base_url TEXT", "requester_pisp_base_url TEXT",
                         "rationale TEXT",
                         "pisp_verdict TEXT",
                         "pisp_rationale TEXT",
                         "pisp_resolved_by TEXT",
                         "escalated_by_role TEXT"):
                try:
                    conn.execute(text(f"ALTER TABLE sa_disputes ADD COLUMN {_col}"))
                except Exception:
                    pass  # column already exists — safe to ignore

    def save_sa_dispute(
        self,
        sa_dispute_id: str,
        dispute_id: str,
        pisp_uri: str,
        escalated_at: str,
        evidence_summary: Optional[str] = None,
        payer_pisp_uri: Optional[str] = None,
        requester_pisp_uri: Optional[str] = None,
        payer_pisp_base_url: Optional[str] = None,
        requester_pisp_base_url: Optional[str] = None,
        pisp_verdict: Optional[str] = None,
        pisp_rationale: Optional[str] = None,
        pisp_resolved_by: Optional[str] = None,
        escalated_by_role: Optional[str] = None,
    ) -> dict:
        """Persist a new SA dispute and return the full row dict."""
        self._ensure_sa_disputes_table()
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO sa_disputes
                        (sa_dispute_id, dispute_id, pisp_uri, escalated_at,
                         status, evidence_summary, payer_pisp_uri, requester_pisp_uri,
                         payer_pisp_base_url, requester_pisp_base_url,
                         pisp_verdict, pisp_rationale, pisp_resolved_by, escalated_by_role)
                    VALUES
                        (:sa_dispute_id, :dispute_id, :pisp_uri, :escalated_at,
                         'UNDER_REVIEW', :evidence_summary, :payer_pisp_uri, :requester_pisp_uri,
                         :payer_pisp_base_url, :requester_pisp_base_url,
                         :pisp_verdict, :pisp_rationale, :pisp_resolved_by, :escalated_by_role)
                """), {
                    "sa_dispute_id": sa_dispute_id,
                    "dispute_id": dispute_id,
                    "pisp_uri": pisp_uri,
                    "escalated_at": escalated_at,
                    "evidence_summary": evidence_summary,
                    "payer_pisp_uri": payer_pisp_uri,
                    "requester_pisp_uri": requester_pisp_uri,
                    "payer_pisp_base_url": payer_pisp_base_url,
                    "requester_pisp_base_url": requester_pisp_base_url,
                    "pisp_verdict": pisp_verdict,
                    "pisp_rationale": pisp_rationale,
                    "pisp_resolved_by": pisp_resolved_by,
                    "escalated_by_role": escalated_by_role,
                })
        return {
            "sa_dispute_id": sa_dispute_id,
            "dispute_id": dispute_id,
            "pisp_uri": pisp_uri,
            "escalated_at": escalated_at,
            "status": "UNDER_REVIEW",
            "evidence_summary": evidence_summary,
            "verdict": None,
            "resolved_at": None,
            "resolved_by": None,
            "payer_pisp_uri": payer_pisp_uri,
            "requester_pisp_uri": requester_pisp_uri,
            "payer_pisp_base_url": payer_pisp_base_url,
            "requester_pisp_base_url": requester_pisp_base_url,
            "pisp_verdict": pisp_verdict,
            "pisp_rationale": pisp_rationale,
            "pisp_resolved_by": pisp_resolved_by,
            "escalated_by_role": escalated_by_role,
        }

    def get_sa_dispute(self, sa_dispute_id: str) -> Optional[dict]:
        self._ensure_sa_disputes_table()
        if not self._engine:
            return None
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM sa_disputes WHERE sa_dispute_id=:id"),
                {"id": sa_dispute_id},
            ).mappings().first()
        return dict(row) if row else None

    def list_sa_disputes(self, status: Optional[str] = None) -> list[dict]:
        self._ensure_sa_disputes_table()
        if not self._engine:
            return []
        q = "SELECT * FROM sa_disputes"
        params: dict = {}
        if status:
            q += " WHERE status=:status"
            params["status"] = status
        q += " ORDER BY escalated_at DESC"
        with self._engine.connect() as conn:
            rows = conn.execute(text(q), params).mappings().all()
        return [dict(r) for r in rows]

    def resolve_sa_dispute(
        self,
        sa_dispute_id: str,
        verdict: str,
        resolved_by: str,
        rationale: str = "",
    ) -> None:
        self._ensure_sa_disputes_table()
        now = _utcnow()
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    UPDATE sa_disputes
                    SET status='RESOLVED', verdict=:verdict,
                        resolved_at=:now, resolved_by=:resolved_by,
                        rationale=:rationale
                    WHERE sa_dispute_id=:id
                """), {
                    "id": sa_dispute_id,
                    "verdict": verdict,
                    "now": now,
                    "resolved_by": resolved_by,
                    "rationale": rationale,
                })

    # ------------------------------------------------------------------
    # Scheme economics — O7 / S5 / X4 / X8
    # ------------------------------------------------------------------
    #
    # Settlement cycle (all timestamps UTC ISO-8601):
    #
    #   transaction_period  — payments settled in this date range are in scope
    #   reporting_window    — PISPs submit one aggregate report per window
    #   reconciliation      — SA flags discrepancies; PISPs may resubmit/amend
    #   payment_window      — net debtor PISPs pay into the SA account
    #   payout_window       — SA distributes to net creditor PISPs
    #
    # Status machine:
    #   transaction_period → reporting → reconciling →
    #   awaiting_payment → paying_out → complete
    # ------------------------------------------------------------------

    def _ensure_economics_tables(self) -> None:
        """Lazily create economics tables and apply column migrations.

        Called at the start of every economics method so the tables are
        created on first use without requiring a restart.
        """
        if not self._engine:
            return
        # Phase 1 — CREATE TABLE (all in one transaction; idempotent)
        with self._engine.begin() as conn:
            # O7 — fee schedule catalogue (named plans; pisp_uri legacy column kept but unused)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS fee_schedules (
                    id             TEXT PRIMARY KEY,
                    pisp_uri       TEXT,        -- legacy; NULL = named catalogue plan
                    rate           REAL NOT NULL,
                    cap_pence      INTEGER NOT NULL,
                    effective_from TEXT NOT NULL,
                    effective_to   TEXT,
                    created_at     TEXT NOT NULL,
                    created_by     TEXT
                )
            """))
            # O7a — named fee plan → PISP assignment mapping
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS pisp_fee_plan_assignments (
                    pisp_uri    TEXT PRIMARY KEY,
                    fee_plan_id TEXT NOT NULL,
                    assigned_at TEXT NOT NULL
                )
            """))
            # S5 — one aggregate report per PISP per window
            # (window phases are computed on-the-fly via window_phases(); no windows table needed)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS pisp_window_reports (
                    id                         TEXT PRIMARY KEY,
                    window_id                  TEXT NOT NULL,
                    pisp_uri                   TEXT NOT NULL,
                    -- Inter-PISP as requester: fees this PISP owes
                    requester_inter_count      INTEGER NOT NULL DEFAULT 0,
                    requester_inter_amount_pence INTEGER NOT NULL DEFAULT 0,
                    requester_inter_fee_pence  INTEGER NOT NULL DEFAULT 0,
                    -- Inter-PISP as payer: fees this PISP has earned
                    payer_inter_count          INTEGER NOT NULL DEFAULT 0,
                    payer_inter_amount_pence   INTEGER NOT NULL DEFAULT 0,
                    payer_inter_fee_pence      INTEGER NOT NULL DEFAULT 0,
                    -- Intra-PISP: fee stays with the PISP (informational)
                    intra_count                INTEGER NOT NULL DEFAULT 0,
                    intra_amount_pence         INTEGER NOT NULL DEFAULT 0,
                    intra_fee_pence            INTEGER NOT NULL DEFAULT 0,
                    -- Net obligation (positive = PISP owes SA; negative = SA owes PISP)
                    net_fee_pence              INTEGER NOT NULL DEFAULT 0,
                    submitted_at               TEXT NOT NULL,  -- UTC ISO-8601
                    amended_count              INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(window_id, pisp_uri)
                )
            """))
            # S5a — per-counterparty breakdown of each window report
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS pisp_window_report_lines (
                    id                      TEXT PRIMARY KEY,
                    window_id               TEXT NOT NULL,
                    reporting_pisp_uri      TEXT NOT NULL,
                    counterparty_pisp_uri   TEXT NOT NULL,
                    requester_count         INTEGER NOT NULL DEFAULT 0,
                    requester_amount_pence  INTEGER NOT NULL DEFAULT 0,
                    requester_fee_pence     INTEGER NOT NULL DEFAULT 0,
                    payer_count             INTEGER NOT NULL DEFAULT 0,
                    payer_amount_pence      INTEGER NOT NULL DEFAULT 0,
                    payer_fee_pence         INTEGER NOT NULL DEFAULT 0,
                    submitted_at            TEXT NOT NULL,
                    UNIQUE(window_id, reporting_pisp_uri, counterparty_pisp_uri)
                )
            """))
            # X8 — net obligation per PISP per window (derived from reports at netting time)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS settlement_obligations (
                    id                TEXT PRIMARY KEY,
                    window_id         TEXT NOT NULL,
                    pisp_uri          TEXT NOT NULL,
                    fees_owed_pence   INTEGER NOT NULL DEFAULT 0,
                    fees_earned_pence INTEGER NOT NULL DEFAULT 0,
                    net_pence         INTEGER NOT NULL DEFAULT 0,
                    status            TEXT NOT NULL DEFAULT 'pending',
                    payment_pr_id     TEXT,
                    created_at        TEXT NOT NULL,  -- UTC ISO-8601
                    settled_at        TEXT,           -- UTC ISO-8601
                    UNIQUE(window_id, pisp_uri)
                )
            """))
        # Phase 2 — ALTER TABLE column additions (each in its own transaction)
        _alters = [
            ("fee_schedules", "name",                  "TEXT"),
            ("fee_schedules", "transaction_fee_pence", "INTEGER NOT NULL DEFAULT 0"),
            ("fee_schedules", "floor_pence",           "INTEGER"),
        ]
        for table, col, col_def in _alters:
            try:
                with self._engine.begin() as conn:
                    conn.execute(text(
                        f"ALTER TABLE {table} ADD COLUMN {col} {col_def}"
                    ))
            except Exception:
                pass  # column already exists

    # ---- Fee plans catalogue (O7) -----------------------------------------

    def get_fee_schedule(self, pisp_uri: str) -> dict:
        """Return the effective fee schedule for pisp_uri.

        Precedence: assigned named plan → hardcoded defaults (5%, 10p cap).
        """
        _hardcoded = {"rate": 0.05, "cap_pence": 10, "transaction_fee_pence": 0, "floor_pence": None}
        if not self._engine:
            return _hardcoded
        self._ensure_economics_tables()
        with self._engine.connect() as conn:
            row = conn.execute(text("""
                SELECT f.*
                  FROM fee_schedules f
                  JOIN pisp_fee_plan_assignments a ON a.fee_plan_id = f.id
                 WHERE a.pisp_uri = :uri
            """), {"uri": pisp_uri}).mappings().first()
        return dict(row) if row else _hardcoded

    # ---- Fee plan catalogue -------------------------------------------------

    def list_fee_plans(self) -> list[dict]:
        """Return all named plans annotated with pisp_count."""
        self._ensure_economics_tables()
        if not self._engine:
            return []
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT f.*,
                       COUNT(a.pisp_uri) AS pisp_count
                  FROM fee_schedules f
                  LEFT JOIN pisp_fee_plan_assignments a ON a.fee_plan_id = f.id
                 WHERE f.pisp_uri IS NULL
                 GROUP BY f.id
                 ORDER BY f.created_at
            """)).mappings().all()
        return [dict(r) for r in rows]

    def create_fee_plan(
        self,
        name: str,
        rate: float,
        cap_pence: int,
        transaction_fee_pence: int = 0,
        floor_pence: Optional[int] = None,
        created_by: str = "",
    ) -> dict:
        """Insert a new named fee plan.  Returns the full row dict."""
        self._ensure_economics_tables()
        plan_id = str(uuid.uuid4())
        now = _utcnow()
        row = {
            "id": plan_id, "pisp_uri": None,
            "name": name, "rate": rate, "cap_pence": cap_pence,
            "transaction_fee_pence": transaction_fee_pence,
            "floor_pence": floor_pence,
            "effective_from": now, "effective_to": None,
            "created_at": now, "created_by": created_by,
        }
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO fee_schedules
                        (id, pisp_uri, name, rate, cap_pence,
                         transaction_fee_pence, floor_pence,
                         effective_from, effective_to, created_at, created_by)
                    VALUES
                        (:id, :pisp_uri, :name, :rate, :cap_pence,
                         :transaction_fee_pence, :floor_pence,
                         :effective_from, :effective_to, :created_at, :created_by)
                """), row)
        return row

    def delete_fee_plan(self, plan_id: str) -> None:
        """Delete a named plan and remove any PISP assignments."""
        self._ensure_economics_tables()
        if self._engine:
            with self._engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM pisp_fee_plan_assignments WHERE fee_plan_id=:id"),
                    {"id": plan_id},
                )
                conn.execute(
                    text("DELETE FROM fee_schedules WHERE id=:id AND pisp_uri IS NULL"),
                    {"id": plan_id},
                )

    def assign_pisp_fee_plan(self, pisp_uri: str, plan_id: Optional[str]) -> None:
        """Assign (or unassign) a fee plan to a PISP."""
        self._ensure_economics_tables()
        if not self._engine:
            return
        with self._engine.begin() as conn:
            if plan_id is None:
                conn.execute(
                    text("DELETE FROM pisp_fee_plan_assignments WHERE pisp_uri=:uri"),
                    {"uri": pisp_uri},
                )
            else:
                conn.execute(text("""
                    INSERT INTO pisp_fee_plan_assignments (pisp_uri, fee_plan_id, assigned_at)
                    VALUES (:uri, :plan_id, :now)
                    ON CONFLICT(pisp_uri) DO UPDATE SET
                        fee_plan_id = excluded.fee_plan_id,
                        assigned_at = excluded.assigned_at
                """), {"uri": pisp_uri, "plan_id": plan_id, "now": _utcnow()})

    def get_pisp_fee_plan_assignment(self, pisp_uri: str) -> Optional[dict]:
        """Return the assigned fee plan dict for a PISP, or None."""
        self._ensure_economics_tables()
        if not self._engine:
            return None
        with self._engine.connect() as conn:
            row = conn.execute(text("""
                SELECT f.*
                  FROM fee_schedules f
                  JOIN pisp_fee_plan_assignments a ON a.fee_plan_id = f.id
                 WHERE a.pisp_uri = :uri
            """), {"uri": pisp_uri}).mappings().first()
        return dict(row) if row else None

    def count_pisps_on_plan(self, plan_id: str) -> int:
        self._ensure_economics_tables()
        if not self._engine:
            return 0
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT COUNT(*) FROM pisp_fee_plan_assignments WHERE fee_plan_id=:id"),
                {"id": plan_id},
            ).first()
        return row[0] if row else 0

    def count_pisps_on_default_fee_plan(self) -> int:
        """Count active PISPs with no fee plan assignment (using scheme default)."""
        if not self._engine:
            return 0
        with self._engine.connect() as conn:
            row = conn.execute(text("""
                SELECT COUNT(*) FROM pisps
                 WHERE status = 'active'
                   AND psp_uri NOT IN (
                       SELECT pisp_uri FROM pisp_fee_plan_assignments
                   )
            """)).first()
        return row[0] if row else 0

    # ---- Settlement windows (O8) ------------------------------------------

    # ---- PISP window reports (S5) -----------------------------------------
    # Window phases are computed via window_phases() / window_status() at module
    # level — no settlement_windows table or methods needed.

    def submit_pisp_window_report(
        self,
        window_id: str,
        pisp_uri: str,
        requester_inter_count: int,
        requester_inter_amount_pence: int,
        requester_inter_fee_pence: int,
        payer_inter_count: int,
        payer_inter_amount_pence: int,
        payer_inter_fee_pence: int,
        intra_count: int,
        intra_amount_pence: int,
        intra_fee_pence: int,
        lines: Optional[list[dict]] = None,
    ) -> dict:
        """Upsert an aggregate window report from a PISP.

        net_fee_pence = requester_inter_fee_pence - payer_inter_fee_pence
        Positive net = PISP owes SA; negative = SA owes PISP.

        ``lines`` is an optional list of per-counterparty dicts:
          { counterparty_pisp_uri, requester_count, requester_amount_pence,
            requester_fee_pence, payer_count, payer_amount_pence, payer_fee_pence }
        When provided the previous lines for this (window, pisp) are replaced.
        """
        self._ensure_economics_tables()
        net_fee_pence = requester_inter_fee_pence - payer_inter_fee_pence
        now = _utcnow()
        row: dict = {
            "id":                            str(uuid.uuid4()),
            "window_id":                     window_id,
            "pisp_uri":                      pisp_uri,
            "requester_inter_count":         requester_inter_count,
            "requester_inter_amount_pence":  requester_inter_amount_pence,
            "requester_inter_fee_pence":     requester_inter_fee_pence,
            "payer_inter_count":             payer_inter_count,
            "payer_inter_amount_pence":      payer_inter_amount_pence,
            "payer_inter_fee_pence":         payer_inter_fee_pence,
            "intra_count":                   intra_count,
            "intra_amount_pence":            intra_amount_pence,
            "intra_fee_pence":               intra_fee_pence,
            "net_fee_pence":                 net_fee_pence,
            "submitted_at":                  now,
            "amended_count":                 0,
        }
        if self._engine:
            with self._engine.begin() as conn:
                # Upsert aggregate report row
                existing = conn.execute(
                    text("SELECT amended_count FROM pisp_window_reports "
                         "WHERE window_id=:wid AND pisp_uri=:uri"),
                    {"wid": window_id, "uri": pisp_uri},
                ).mappings().first()
                if existing:
                    row["amended_count"] = (existing["amended_count"] or 0) + 1
                    conn.execute(text("""
                        UPDATE pisp_window_reports SET
                            requester_inter_count=:requester_inter_count,
                            requester_inter_amount_pence=:requester_inter_amount_pence,
                            requester_inter_fee_pence=:requester_inter_fee_pence,
                            payer_inter_count=:payer_inter_count,
                            payer_inter_amount_pence=:payer_inter_amount_pence,
                            payer_inter_fee_pence=:payer_inter_fee_pence,
                            intra_count=:intra_count,
                            intra_amount_pence=:intra_amount_pence,
                            intra_fee_pence=:intra_fee_pence,
                            net_fee_pence=:net_fee_pence,
                            submitted_at=:submitted_at,
                            amended_count=:amended_count
                        WHERE window_id=:window_id AND pisp_uri=:pisp_uri
                    """), row)
                else:
                    conn.execute(text("""
                        INSERT INTO pisp_window_reports
                            (id, window_id, pisp_uri,
                             requester_inter_count, requester_inter_amount_pence, requester_inter_fee_pence,
                             payer_inter_count, payer_inter_amount_pence, payer_inter_fee_pence,
                             intra_count, intra_amount_pence, intra_fee_pence,
                             net_fee_pence, submitted_at, amended_count)
                        VALUES
                            (:id, :window_id, :pisp_uri,
                             :requester_inter_count, :requester_inter_amount_pence, :requester_inter_fee_pence,
                             :payer_inter_count, :payer_inter_amount_pence, :payer_inter_fee_pence,
                             :intra_count, :intra_amount_pence, :intra_fee_pence,
                             :net_fee_pence, :submitted_at, :amended_count)
                    """), row)
                # Replace per-counterparty lines (delete + re-insert handles amendments)
                if lines is not None:
                    conn.execute(
                        text("DELETE FROM pisp_window_report_lines "
                             "WHERE window_id=:wid AND reporting_pisp_uri=:uri"),
                        {"wid": window_id, "uri": pisp_uri},
                    )
                    for ln in lines:
                        conn.execute(text("""
                            INSERT INTO pisp_window_report_lines
                                (id, window_id, reporting_pisp_uri, counterparty_pisp_uri,
                                 requester_count, requester_amount_pence, requester_fee_pence,
                                 payer_count, payer_amount_pence, payer_fee_pence, submitted_at)
                            VALUES
                                (:id, :window_id, :reporting_pisp_uri, :counterparty_pisp_uri,
                                 :requester_count, :requester_amount_pence, :requester_fee_pence,
                                 :payer_count, :payer_amount_pence, :payer_fee_pence, :submitted_at)
                        """), {
                            "id":                    str(uuid.uuid4()),
                            "window_id":             window_id,
                            "reporting_pisp_uri":    pisp_uri,
                            "counterparty_pisp_uri": ln["counterparty_pisp_uri"],
                            "requester_count":       int(ln.get("requester_count", 0)),
                            "requester_amount_pence": int(ln.get("requester_amount_pence", 0)),
                            "requester_fee_pence":   int(ln.get("requester_fee_pence", 0)),
                            "payer_count":           int(ln.get("payer_count", 0)),
                            "payer_amount_pence":    int(ln.get("payer_amount_pence", 0)),
                            "payer_fee_pence":       int(ln.get("payer_fee_pence", 0)),
                            "submitted_at":          now,
                        })
        return row

    def get_peer_status(self, window_id: str, pisp_uri: str) -> list[dict]:
        """Return bilateral reconciliation status for each counterparty PISP.

        For each counterparty C that appears in pisp_uri's report lines:
          - your_requester_fee_pence: what pisp_uri says it owes C
          - your_payer_fee_pence:     what pisp_uri says C owes it
          - their_requester_fee_pence: what C says it owes pisp_uri (None if not filed)
          - their_payer_fee_pence:     what C says pisp_uri owes it (None if not filed)
          - status: 'waiting' | 'matched' | 'discrepancy'
        """
        self._ensure_economics_tables()
        if not self._engine:
            return []
        with self._engine.connect() as conn:
            # My lines
            my_lines = conn.execute(text("""
                SELECT * FROM pisp_window_report_lines
                 WHERE window_id=:wid AND reporting_pisp_uri=:uri
                 ORDER BY counterparty_pisp_uri
            """), {"wid": window_id, "uri": pisp_uri}).mappings().all()

            # All lines from counterparties that reference pisp_uri
            mirror_lines = conn.execute(text("""
                SELECT * FROM pisp_window_report_lines
                 WHERE window_id=:wid AND counterparty_pisp_uri=:uri
            """), {"wid": window_id, "uri": pisp_uri}).mappings().all()

        mirror_by_cp = {r["reporting_pisp_uri"]: dict(r) for r in mirror_lines}

        result = []
        for line in my_lines:
            cp = line["counterparty_pisp_uri"]
            mirror = mirror_by_cp.get(cp)
            my_req  = line["requester_fee_pence"]
            my_pay  = line["payer_fee_pence"]
            th_req  = mirror["requester_fee_pence"] if mirror else None
            th_pay  = mirror["payer_fee_pence"]     if mirror else None

            if mirror is None:
                status = "waiting"
            elif my_req == th_pay and my_pay == th_req:
                status = "matched"
            else:
                status = "discrepancy"

            result.append({
                "counterparty_pisp_uri":    cp,
                "your_requester_fee_pence": my_req,
                "your_payer_fee_pence":     my_pay,
                "their_requester_fee_pence": th_req,
                "their_payer_fee_pence":    th_pay,
                "status":                   status,
            })
        return result

    def get_pisp_window_report(self, window_id: str, pisp_uri: str) -> Optional[dict]:
        """Return the aggregate report plus per-counterparty lines, or None."""
        self._ensure_economics_tables()
        if not self._engine:
            return None
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM pisp_window_reports "
                     "WHERE window_id=:wid AND pisp_uri=:uri"),
                {"wid": window_id, "uri": pisp_uri},
            ).mappings().first()
            if not row:
                return None
            result = dict(row)
            line_rows = conn.execute(
                text("SELECT counterparty_pisp_uri, "
                     "requester_count, requester_amount_pence, requester_fee_pence, "
                     "payer_count, payer_amount_pence, payer_fee_pence "
                     "FROM pisp_window_report_lines "
                     "WHERE window_id=:wid AND reporting_pisp_uri=:uri "
                     "ORDER BY counterparty_pisp_uri"),
                {"wid": window_id, "uri": pisp_uri},
            ).mappings().all()
            result["lines"] = [dict(r) for r in line_rows]
        return result

    def list_pisp_window_reports(self, window_id: str) -> list[dict]:
        self._ensure_economics_tables()
        if not self._engine:
            return []
        with self._engine.connect() as conn:
            rows = conn.execute(
                text("SELECT * FROM pisp_window_reports "
                     "WHERE window_id=:wid ORDER BY pisp_uri"),
                {"wid": window_id},
            ).mappings().all()
        return [dict(r) for r in rows]

    # ---- Netting and obligations (X4 / X8) ----------------------------------

    def calculate_netting(self, window_id: str) -> list[dict]:
        """Derive net settlement obligations from submitted PISP window reports.

        For each PISP that has submitted a report:
          net = requester_inter_fee_pence - payer_inter_fee_pence
          positive = PISP owes SA; negative = SA owes PISP

        Upserts into settlement_obligations.  Returns list of obligation dicts.
        """
        self._ensure_economics_tables()
        if not self._engine:
            return []
        reports = self.list_pisp_window_reports(window_id)
        now = _utcnow()
        obligations = []
        with self._engine.begin() as conn:
            for r in reports:
                pisp_uri = r["pisp_uri"]
                fees_owed   = r["requester_inter_fee_pence"]
                fees_earned = r["payer_inter_fee_pence"]
                net         = fees_owed - fees_earned
                ob = {
                    "id":                str(uuid.uuid4()),
                    "window_id":         window_id,
                    "pisp_uri":          pisp_uri,
                    "fees_owed_pence":   fees_owed,
                    "fees_earned_pence": fees_earned,
                    "net_pence":         net,
                    "status":            "pending",
                    "payment_pr_id":     None,
                    "created_at":        now,
                    "settled_at":        None,
                }
                conn.execute(text("""
                    INSERT INTO settlement_obligations
                        (id, window_id, pisp_uri, fees_owed_pence, fees_earned_pence,
                         net_pence, status, payment_pr_id, created_at)
                    VALUES
                        (:id, :window_id, :pisp_uri, :fees_owed_pence, :fees_earned_pence,
                         :net_pence, :status, :payment_pr_id, :created_at)
                    ON CONFLICT(window_id, pisp_uri) DO UPDATE SET
                        fees_owed_pence=excluded.fees_owed_pence,
                        fees_earned_pence=excluded.fees_earned_pence,
                        net_pence=excluded.net_pence
                """), ob)
                obligations.append(ob)
        return obligations

    def list_settlement_obligations(self, window_id: str) -> list[dict]:
        self._ensure_economics_tables()
        if not self._engine:
            return []
        with self._engine.connect() as conn:
            rows = conn.execute(
                text("SELECT * FROM settlement_obligations "
                     "WHERE window_id=:wid ORDER BY pisp_uri"),
                {"wid": window_id},
            ).mappings().all()
        return [dict(r) for r in rows]

    def get_obligation_by_pr_id(self, payment_pr_id: str) -> Optional[dict]:
        """X8 — look up a settlement obligation by its Requester Interface payment_request_id."""
        self._ensure_economics_tables()
        if not self._engine:
            return None
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM settlement_obligations WHERE payment_pr_id=:prid"),
                {"prid": payment_pr_id},
            ).mappings().first()
        return dict(row) if row else None

    def update_obligation_status(
        self,
        obligation_id: str,
        status: str,
        payment_pr_id: Optional[str] = None,
    ) -> None:
        self._ensure_economics_tables()
        if not self._engine:
            return
        now = _utcnow()
        extra = ", payment_pr_id=:prid" if payment_pr_id else ""
        extra += ", settled_at=:now" if status == "settled" else ""
        with self._engine.begin() as conn:
            conn.execute(
                text(f"UPDATE settlement_obligations SET status=:status{extra} WHERE id=:id"),
                {"id": obligation_id, "status": status,
                 "prid": payment_pr_id, "now": now},
            )

    # ---- (legacy) ------------------------------------------------------------
    # save_compliance_report / list_compliance_reports / reconcile_compliance_reports
    # get_or_create_window / update_settlement_window_status
    # These methods have been removed; the new pisp_window_reports flow
    # replaced them.  Old compliance_reports rows (if any) remain in the DB
    # but are no longer read or written.

    # ------------------------------------------------------------------
    # Seed support — import pre-generated PISP records at first startup
    # ------------------------------------------------------------------

    def seed_from_file(self, seed_path: str) -> int:
        """Import PISP records from sa_seed.json if the pisps table is empty.

        Returns the number of records imported (0 if table was already populated).
        """
        if not self._engine:
            return 0
        with self._engine.connect() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM pisps")).scalar()
        if count and count > 0:
            return 0   # already seeded

        import json as _json
        from pathlib import Path
        records = _json.loads(Path(seed_path).read_text())
        now = _utcnow()
        imported = 0
        with self._engine.begin() as conn:
            for rec in records:
                pisp_id = str(uuid.uuid4())
                conn.execute(text("""
                    INSERT INTO pisps
                        (id, psp_uri, name, base_url, status,
                         pisp_ca_cert, serial_hex, registered_at, approved_at)
                    VALUES
                        (:id, :psp_uri, :name, :base_url, 'active',
                         :pisp_ca_cert, :serial_hex, :now, :now)
                """), {
                    "id": pisp_id,
                    "psp_uri":      rec["psp_uri"],
                    "name":         rec["name"],
                    "base_url":     rec["base_url"],
                    "pisp_ca_cert": rec["pisp_ca_cert"],
                    "serial_hex":   rec["serial_hex"],
                    "now":          now,
                })
                imported += 1
        return imported
