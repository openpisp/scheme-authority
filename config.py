"""
Scheme Authority — configuration from environment variables.
"""

from __future__ import annotations
import os
from urllib.parse import urlparse

# Service identity
SA_BASE_URL: str = os.getenv("SA_BASE_URL", "http://scheme-authority.openpisp.local")

# Scheme Authority Protocol (SAP, formerly Protocol E) — SA's own scheme URI.
# Uses the sa:// scheme (not psp://) to distinguish the Scheme Authority from
# member PISPs in the directory and in SAP JWS iss claims.
SA_PISP_URI: str = os.getenv("SA_PISP_URI") or ("sa://" + urlparse(SA_BASE_URL).hostname)

# SAP signing — when true the SA signs outbound notifications to PISPs.
# New name: PSP_SAP_SIGNING_ENABLED.  Old name: PSP_E_SIGNING_ENABLED (kept as fallback).
PSP_E_SIGNING_ENABLED: bool = (
    os.getenv("PSP_SAP_SIGNING_ENABLED") or os.getenv("PSP_E_SIGNING_ENABLED") or "false"
).lower() in ("true", "1", "yes")

# Database — full URL takes precedence; falls back to DB_HOST/DB_PASSWORD/DB_USER
def _resolve_db_url(env_key: str, db_name: str) -> str | None:
    url = os.getenv(env_key)
    if url:
        return url
    host = os.getenv("DB_HOST")
    if host:
        user = os.getenv("DB_USER", "openpisp")
        pw   = os.getenv("DB_PASSWORD", "")
        port = os.getenv("DB_PORT", "5432")
        return f"postgresql://{user}:{pw}@{host}:{port}/{db_name}"
    return None

SA_DB_URL: str | None = _resolve_db_url("SA_DB_URL", "scheme_authority")

# Auto-approve mode — set to true in dev so PISPs are approved immediately on
# registration (no manual operator step required).  Must be false in production.
SA_AUTO_APPROVE: bool = os.getenv("SA_AUTO_APPROVE", "false").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# PKI — intermediate CA key + cert, root CA cert
#
# Priority (highest first):
#   1. PEM content env var  (INTERMEDIATE_CA_KEY / INTERMEDIATE_CA_CERT / ROOT_CA_CERT)
#      Injected by ECS from Secrets Manager / SSM — useful for cloud deployments
#      where the cert is managed externally.
#   2. File path env var    (*_FILE)
#      Local dev: docker-compose mounts the generated files into the container.
#      AWS cold-start: SA writes its self-generated key to INTERMEDIATE_CA_KEY_FILE
#      and, once the signed cert is uploaded, to INTERMEDIATE_CA_CERT_FILE too.
#
# Self-generation behaviour (cold start):
#   If no key is available from either source, the SA generates an EC P-384
#   key + CSR, writes the key to INTERMEDIATE_CA_KEY_FILE, logs the CSR PEM
#   prominently, and starts in degraded mode (cert issuance returns 503).
#   Once the operator uploads the signed cert via POST /scheme/admin/pki/cert
#   the SA reloads and resumes normal operation.
# ---------------------------------------------------------------------------

# PEM content env vars (takes priority over file paths)
INTERMEDIATE_CA_KEY:  str | None = os.getenv("INTERMEDIATE_CA_KEY")  or None
INTERMEDIATE_CA_CERT: str | None = os.getenv("INTERMEDIATE_CA_CERT") or None
ROOT_CA_CERT:         str | None = os.getenv("ROOT_CA_CERT")         or None

# File path env vars (local dev / AWS persistent key on EFS)
INTERMEDIATE_CA_KEY_FILE:  str | None = os.getenv("INTERMEDIATE_CA_KEY_FILE")  or None
INTERMEDIATE_CA_CERT_FILE: str | None = os.getenv("INTERMEDIATE_CA_CERT_FILE") or None
ROOT_CA_CERT_FILE:         str | None = os.getenv("ROOT_CA_CERT_FILE")         or None

# CRL validity window
CRL_NEXT_UPDATE_HOURS: int = int(os.getenv("CRL_NEXT_UPDATE_HOURS", "24"))

# Operator admin credentials (Scheme Authority admin UI)
OPERATOR_EMAIL: str = os.getenv("OPERATOR_EMAIL", "admin@scheme.openpisp.local")
OPERATOR_PASSWORD: str = os.getenv("OPERATOR_PASSWORD", "scheme-admin-password")
SA_JWT_SECRET: str = os.getenv("SA_JWT_SECRET", "dev-sa-secret-change-in-production")
SA_JWT_ALGORITHM: str = "HS256"
SA_JWT_EXPIRE_MINUTES: int = 60 * 8   # 8-hour admin sessions

# ---------------------------------------------------------------------------
# Scheme economics — default fee schedule (O7)
#
# scheme_fee = min(floor(amount_pence × SCHEME_FEE_RATE), SCHEME_FEE_CAP_PENCE)
# Applies to all settled transactions (intra and inter-PISP).
# For inter-PISP transactions, the fee is owed by the requester PISP
# and earned by the payer PISP; the SA is a pass-through clearing house.
# ---------------------------------------------------------------------------
SCHEME_FEE_RATE:      float = float(os.getenv("SCHEME_FEE_RATE",      "0.05"))   # 5 %
SCHEME_FEE_CAP_PENCE: int   = int(  os.getenv("SCHEME_FEE_CAP_PENCE", "10"))    # 10 p

# ---------------------------------------------------------------------------
# SA settlement account — used for dogfooding (X8)
#
# The SA holds an account on its home PISP.  Net debtor PISPs pay into this
# account; the SA distributes from it to net creditor PISPs.
# ---------------------------------------------------------------------------
SA_HOME_PISP_URL:              str | None = os.getenv("SA_HOME_PISP_URL")        or None
SA_HOME_PISP_TERMINAL_URI:     str | None = os.getenv("SA_HOME_PISP_TERMINAL_URI") or None
SA_HOME_PISP_CLIENT_ID:        str | None = os.getenv("SA_HOME_PISP_CLIENT_ID")   or None  # terminal UUID shown as "Client ID" in portal
SA_HOME_PISP_API_KEY:          str | None = os.getenv("SA_HOME_PISP_API_KEY")     or None
SA_SETTLEMENT_SORT_CODE:       str | None = os.getenv("SA_SETTLEMENT_SORT_CODE") or None
SA_SETTLEMENT_ACCOUNT_NUMBER:  str | None = os.getenv("SA_SETTLEMENT_ACCOUNT_NUMBER") or None
SA_SETTLEMENT_ACCOUNT_NAME:    str        = os.getenv("SA_SETTLEMENT_ACCOUNT_NAME", "OpenPISP Scheme Authority")

# ---------------------------------------------------------------------------
# Settlement cycle timing — all phases in UTC.
#
# A full cycle for calendar month M:
#   transaction_period  : M/01 00:00:00Z → M/last 23:59:59Z
#   reporting_window    : transaction_period_end+1s → +REPORTING_DAYS
#                         PISPs must submit their aggregate window report.
#   reconciliation      : reporting_closes+1s → +RECONCILE_DAYS
#                         SA flags discrepancies; PISPs may resubmit.
#   payment_window      : reconciliation_closes+1s → +PAYMENT_DAYS
#                         Net debtor PISPs transfer to SA settlement account.
#   payout_window       : payment_due+1s → +PAYOUT_DAYS
#                         SA distributes to net creditor PISPs.
#
# All values are calendar days.  Override via env vars.
# ---------------------------------------------------------------------------
SETTLEMENT_REPORTING_DAYS:  int = int(os.getenv("SETTLEMENT_REPORTING_DAYS",  "7"))
SETTLEMENT_RECONCILE_DAYS:  int = int(os.getenv("SETTLEMENT_RECONCILE_DAYS",  "3"))
SETTLEMENT_PAYMENT_DAYS:    int = int(os.getenv("SETTLEMENT_PAYMENT_DAYS",    "7"))
SETTLEMENT_PAYOUT_DAYS:     int = int(os.getenv("SETTLEMENT_PAYOUT_DAYS",     "7"))
