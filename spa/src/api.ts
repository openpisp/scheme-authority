/**
 * SA admin portal JSON API client.
 * All calls use credentials:'include' so the sa_admin_session cookie
 * is sent automatically. A 401 redirects to the login screen.
 */

const BASE = '/admin/api'

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

export async function saFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (res.status === 401) {
    // Signal App to show login form
    window.dispatchEvent(new CustomEvent('sa:unauthorized'))
    throw new ApiError(401, 'Session expired')
  }
  if (!res.ok) {
    const text = await res.text().catch(() => `HTTP ${res.status}`)
    throw new ApiError(res.status, text)
  }
  return res.json() as Promise<T>
}

// ── Types ──────────────────────────────────────────────────────────────────

export interface Me {
  email: string
}

export type PISPStatus = 'pending' | 'active' | 'suspended' | 'revoked'

export interface PISPSummary {
  id: string
  psp_uri: string
  name: string
  base_url: string
  b_url: string | null
  status: PISPStatus
  registered_at: string
  approved_at: string | null
  revoked_at: string | null
  revoke_reason: string | null
  suspended_at: string | null
  suspend_reason: string | null
  cert_days: number | null
  fee_plan: SAFeePlan | null
}

export interface CertInfo {
  subject: string
  issuer: string
  not_valid_before: string
  not_valid_after: string
  psp_uri_san: string | null
  revoked: boolean
  days_remaining: number
  pem: string
}

export interface PISPDetail extends PISPSummary {
  cert: CertInfo | null
}

export interface PKIHealth {
  warnings: string[]
  intermediate_days: number | null
  protocol_e_days: number | null
  signing_enabled: boolean
  intermediate_loaded: boolean
  crl_next_update_hours: number
}

export interface CRLStatus {
  issuer: string | null
  last_update: string
  next_update: string
  entry_count: number
  crl_number: number
  intermediate_loaded: boolean
  entries: { serial_hex: string; revoked_at: string }[]
}

export interface Dispute {
  sa_dispute_id: string
  dispute_id: string
  pisp_uri: string
  escalated_at: string
  status: string
  verdict: string | null
  resolved_at: string | null
  rationale: string | null
  evidence_summary: string | null
  payer_pisp_uri: string | null
  requester_pisp_uri: string | null
}

export interface NetworkStats {
  pisps: {
    active: number
    pending: number
    suspended: number
    revoked: number
    total: number
  }
  disputes: {
    under_review: number
    resolved: number
    total: number
  }
  crl_entries: number
}

// ── Economics ──────────────────────────────────────────────────────────────

export interface SAFeePlan {
  id: string
  name: string
  rate: number                    // e.g. 0.05 = 5%
  cap_pence: number               // e.g. 10
  transaction_fee_pence: number
  floor_pence: number | null
  pisp_count: number
  is_default?: boolean            // true for synthetic __default__ row
  created_at: string | null
}

// All phase timestamps are UTC ISO-8601 strings.
export type WindowStatus =
  | 'transaction_period'
  | 'reporting'
  | 'reconciling'
  | 'awaiting_payment'
  | 'paying_out'
  | 'complete'

export interface WindowPhases {
  window_id: string                   // e.g. '2026-05'
  year: number
  month: number
  transaction_period_start: string    // UTC ISO-8601
  transaction_period_end: string
  reporting_opens_at: string
  reporting_closes_at: string
  reconciliation_closes_at: string
  payment_due_by: string
  settlement_due_by: string
  status: WindowStatus
  // Only on list endpoint (annotated by SA admin API)
  report_count?: number
  obligation_count?: number
}

export interface PISPWindowReport {
  id: string
  window_id: string
  pisp_uri: string
  requester_inter_count: number
  requester_inter_amount_pence: number
  requester_inter_fee_pence: number
  payer_inter_count: number
  payer_inter_amount_pence: number
  payer_inter_fee_pence: number
  intra_count: number
  intra_amount_pence: number
  intra_fee_pence: number
  net_fee_pence: number               // positive = PISP owes SA; negative = SA owes PISP
  submitted_at: string                // UTC ISO-8601
  amended_count: number
}

export interface SettlementObligation {
  id: string
  window_id: string
  pisp_uri: string
  fees_owed_pence: number
  fees_earned_pence: number
  net_pence: number                   // positive = PISP owes SA; negative = SA owes PISP
  status: 'pending' | 'instructed' | 'collecting' | 'payout_pending' | 'settled'
  payment_pr_id: string | null
  created_at: string
  settled_at: string | null
}

export interface WindowDetail extends WindowPhases {
  reports: PISPWindowReport[]
  report_count: number
  obligations: SettlementObligation[]
  total_owed_pence: number
  total_earned_pence: number
  discrepancy_pence: number           // ideally 0 after reconciliation
}

export interface ExecutePaymentsResult {
  window_id: string
  executed: number
  payout_pending: number
  errors: string[]
}

// ── X8 Settlement ─────────────────────────────────────────────────────────────

export function executeSettlementPayments(windowId: string): Promise<ExecutePaymentsResult> {
  return saFetch<ExecutePaymentsResult>(
    `/economics/windows/${windowId}/execute-payments`,
    { method: 'POST' },
  )
}

export function obligationInvoiceUrl(windowId: string, obligationId: string): string {
  return `/admin/api/economics/windows/${windowId}/obligations/${obligationId}/invoice`
}
