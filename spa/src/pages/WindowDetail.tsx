import { useState, useEffect, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  saFetch,
  executeSettlementPayments,
  obligationInvoiceUrl,
  type WindowDetail as WindowDetailData,
  type SettlementObligation,
} from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { AlertTriangle, ArrowLeft, Calculator, FileText, Send, Zap } from 'lucide-react'

// ── helpers ──────────────────────────────────────────────────────────────────

function pence(p: number): string {
  if (p === 0) return '0p'
  const abs = Math.abs(p)
  const sign = p < 0 ? '−' : ''
  if (abs < 100) return `${sign}${abs}p`
  return `${sign}£${(abs / 100).toFixed(2)}`
}

const MONTH_NAMES = [
  '', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
]

type WindowStatus = WindowDetailData['status']

function WindowStatusBadge({ status }: { status: WindowStatus }) {
  const map: Record<string, string> = {
    transaction_period: 'bg-slate-100 text-slate-700',
    reporting:          'bg-sky-100 text-sky-800',
    reconciling:        'bg-amber-100 text-amber-800',
    awaiting_payment:   'bg-orange-100 text-orange-800',
    paying_out:         'bg-violet-100 text-violet-800',
    complete:           'bg-emerald-100 text-emerald-800',
  }
  const label: Record<string, string> = {
    transaction_period: 'Collecting',
    reporting:          'Reporting',
    reconciling:        'Reconciling',
    awaiting_payment:   'Awaiting payment',
    paying_out:         'Paying out',
    complete:           'Complete',
  }
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${map[status] ?? 'bg-muted text-muted-foreground'}`}>
      {label[status] ?? status}
    </span>
  )
}

function ObligationStatusBadge({ status }: { status: SettlementObligation['status'] }) {
  const map: Record<string, string> = {
    pending:        'bg-slate-100 text-slate-700',
    instructed:     'bg-violet-100 text-violet-800',
    collecting:     'bg-blue-100 text-blue-800',
    payout_pending: 'bg-amber-100 text-amber-800',
    settled:        'bg-emerald-100 text-emerald-800',
  }
  const label: Record<string, string> = {
    pending:        'Pending',
    instructed:     'Instructed',
    collecting:     'Collecting',
    payout_pending: 'Payout pending',
    settled:        'Settled',
  }
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${map[status] ?? 'bg-muted text-muted-foreground'}`}>
      {status === 'collecting' && (
        <span className="mr-1 h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
      )}
      {label[status] ?? status}
    </span>
  )
}

// ── Phase timeline ────────────────────────────────────────────────────────────

type PhaseRow = {
  label: string
  from: string
  to: string
  statusKey: WindowStatus
}

function PhaseTimeline({ data }: { data: WindowDetailData }) {
  const phases: PhaseRow[] = [
    {
      label: 'Transaction period',
      from: data.transaction_period_start,
      to: data.transaction_period_end,
      statusKey: 'transaction_period',
    },
    {
      label: 'Reporting window',
      from: data.reporting_opens_at,
      to: data.reporting_closes_at,
      statusKey: 'reporting',
    },
    {
      label: 'Reconciliation',
      from: data.reporting_closes_at,
      to: data.reconciliation_closes_at,
      statusKey: 'reconciling',
    },
    {
      label: 'Payment window',
      from: data.reconciliation_closes_at,
      to: data.payment_due_by,
      statusKey: 'awaiting_payment',
    },
    {
      label: 'Settlement payout',
      from: data.payment_due_by,
      to: data.settlement_due_by,
      statusKey: 'paying_out',
    },
  ]

  const fmt = (iso: string) =>
    new Date(iso).toLocaleString(undefined, {
      day: 'numeric', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
    })

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold">Settlement cycle</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Phase</TableHead>
              <TableHead>Opens (UTC)</TableHead>
              <TableHead>Closes (UTC)</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {phases.map(p => {
              const active = data.status === p.statusKey
              return (
                <TableRow key={p.statusKey} className={active ? 'bg-primary/5' : ''}>
                  <TableCell className="font-medium text-sm">
                    <span className="flex items-center gap-2">
                      {active && (
                        <span className="inline-block h-1.5 w-1.5 rounded-full bg-primary" />
                      )}
                      {p.label}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{fmt(p.from)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{fmt(p.to)}</TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function WindowDetail() {
  const { window_id } = useParams<{ window_id: string }>()
  const [data, setData]       = useState<WindowDetailData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [acting, setActing]   = useState<'calculate' | 'instruct' | 'execute' | null>(null)

  const load = useCallback(() => {
    if (!window_id) return
    setLoading(true)
    saFetch<WindowDetailData>(`/economics/windows/${window_id}`)
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [window_id])

  useEffect(load, [load])

  const handleCalculate = async () => {
    if (!window_id) return
    setActing('calculate')
    try {
      await saFetch(`/economics/windows/${window_id}/calculate`, { method: 'POST' })
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error')
    } finally { setActing(null) }
  }

  const handleInstruct = async () => {
    if (!window_id) return
    if (!confirm('Mark all pending obligations as instructed and initiate settlement payments?')) return
    setActing('instruct')
    try {
      await saFetch(`/economics/windows/${window_id}/instruct`, { method: 'POST' })
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error')
    } finally { setActing(null) }
  }

  const handleExecute = async () => {
    if (!window_id) return
    if (!confirm('Create Protocol A payment requests at the SA home PISP for all instructed debit obligations?')) return
    setActing('execute')
    try {
      const result = await executeSettlementPayments(window_id)
      if (result.errors.length > 0) {
        setError(`Executed ${result.executed} payment(s), but ${result.errors.length} failed: ${result.errors.join('; ')}`)
      }
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Error')
    } finally { setActing(null) }
  }

  // Derived flags
  const canCalculate = data !== null &&
    (data.status === 'reconciling' || data.status === 'awaiting_payment' || data.status === 'paying_out' || data.status === 'complete') &&
    data.report_count > 0

  const canInstruct = data !== null &&
    data.obligations.some(o => o.status === 'pending') &&
    (data.status === 'awaiting_payment' || data.status === 'paying_out' || data.status === 'complete')

  const canExecute = data !== null &&
    data.obligations.some(o => o.status === 'instructed')

  return (
    <main className="mx-auto max-w-5xl px-6 py-8 space-y-6">
      {/* Back */}
      <Link
        to="/economics"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Settlement Windows
      </Link>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {loading && !data ? (
        <div className="space-y-3">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : data ? (
        <>
          {/* Header */}
          <div className="flex items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold">
                {MONTH_NAMES[data.month]} {data.year}
              </h1>
              <div className="mt-1">
                <WindowStatusBadge status={data.status} />
              </div>
            </div>
            <div className="flex items-center gap-2">
              {canCalculate && (
                <button
                  onClick={handleCalculate}
                  disabled={acting !== null}
                  className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  <Calculator className="h-3.5 w-3.5" />
                  {acting === 'calculate' ? 'Calculating…' : 'Calculate netting'}
                </button>
              )}
              {canInstruct && (
                <button
                  onClick={handleInstruct}
                  disabled={acting !== null}
                  className="flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-sm font-medium hover:bg-muted disabled:opacity-50 transition-colors"
                >
                  <Send className="h-3.5 w-3.5" />
                  {acting === 'instruct' ? 'Instructing…' : 'Instruct payments'}
                </button>
              )}
              {canExecute && (
                <button
                  onClick={handleExecute}
                  disabled={acting !== null}
                  className="flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  <Zap className="h-3.5 w-3.5" />
                  {acting === 'execute' ? 'Executing…' : 'Execute payments'}
                </button>
              )}
            </div>
          </div>

          {/* Summary cards */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <SummaryCard label="Reports" value={String(data.report_count)} />
            <SummaryCard label="Total owed" value={pence(data.total_owed_pence)} />
            <SummaryCard label="Total earned" value={pence(data.total_earned_pence)} />
            <SummaryCard
              label="Discrepancy"
              value={pence(data.discrepancy_pence)}
              warn={data.discrepancy_pence !== 0}
            />
          </div>

          {data.discrepancy_pence !== 0 && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                Network discrepancy of {pence(data.discrepancy_pence)} detected — fees reported as owed by
                PISPs do not match fees reported as earned. Reconciliation required.
              </AlertDescription>
            </Alert>
          )}

          {/* Phase timeline */}
          <PhaseTimeline data={data} />

          {/* PISP reports */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">
                PISP reports
                {data.report_count > 0 && (
                  <span className="ml-2 text-xs font-normal text-muted-foreground">
                    {data.report_count} submitted
                  </span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {data.reports.length === 0 ? (
                <p className="px-6 py-4 text-xs text-muted-foreground">
                  {data.status === 'transaction_period'
                    ? 'Reporting opens at the end of the transaction period.'
                    : 'No reports submitted yet.'}
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>PISP</TableHead>
                      <TableHead className="text-right">Req. inter txns</TableHead>
                      <TableHead className="text-right">Req. inter fees</TableHead>
                      <TableHead className="text-right">Payer inter txns</TableHead>
                      <TableHead className="text-right">Payer inter fees</TableHead>
                      <TableHead className="text-right">Intra txns</TableHead>
                      <TableHead className="text-right">Net fee</TableHead>
                      <TableHead className="text-right">Amendments</TableHead>
                      <TableHead>Submitted</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.reports.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-mono text-xs" title={r.pisp_uri}>
                          {r.pisp_uri.replace(/^psp:\/\//, '')}
                        </TableCell>
                        <TableCell className="text-right text-xs">
                          {r.requester_inter_count.toLocaleString()}
                        </TableCell>
                        <TableCell className="text-right text-xs font-medium">
                          {pence(r.requester_inter_fee_pence)}
                        </TableCell>
                        <TableCell className="text-right text-xs">
                          {r.payer_inter_count.toLocaleString()}
                        </TableCell>
                        <TableCell className="text-right text-xs font-medium">
                          {pence(r.payer_inter_fee_pence)}
                        </TableCell>
                        <TableCell className="text-right text-xs">
                          {r.intra_count.toLocaleString()}
                        </TableCell>
                        <TableCell className={`text-right text-xs font-semibold ${r.net_fee_pence > 0 ? 'text-red-600' : r.net_fee_pence < 0 ? 'text-emerald-700' : ''}`}>
                          {pence(r.net_fee_pence)}
                        </TableCell>
                        <TableCell className="text-right text-xs text-muted-foreground">
                          {r.amended_count > 0 ? r.amended_count : '—'}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {new Date(r.submitted_at).toLocaleDateString()}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* Obligations */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Settlement obligations</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {data.obligations.length === 0 ? (
                <p className="px-6 py-4 text-xs text-muted-foreground">
                  {data.report_count === 0
                    ? 'No reports yet — obligations are calculated from submitted reports.'
                    : 'Run "Calculate netting" to generate obligations from submitted reports.'}
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>PISP</TableHead>
                      <TableHead className="text-right">Fees owed</TableHead>
                      <TableHead className="text-right">Fees earned</TableHead>
                      <TableHead className="text-right">Net</TableHead>
                      <TableHead>Direction</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Invoice</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.obligations.map(o => (
                      <TableRow key={o.id}>
                        <TableCell className="font-mono text-xs" title={o.pisp_uri}>
                          {o.pisp_uri.replace(/^psp:\/\//, '')}
                        </TableCell>
                        <TableCell className="text-right text-xs font-medium text-red-600">
                          {pence(o.fees_owed_pence)}
                        </TableCell>
                        <TableCell className="text-right text-xs font-medium text-emerald-700">
                          {pence(o.fees_earned_pence)}
                        </TableCell>
                        <TableCell className={`text-right text-xs font-semibold ${o.net_pence > 0 ? 'text-red-600' : o.net_pence < 0 ? 'text-emerald-700' : ''}`}>
                          {pence(o.net_pence)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {o.net_pence > 0
                            ? '← owes SA'
                            : o.net_pence < 0
                              ? '→ SA pays PISP'
                              : 'balanced'}
                        </TableCell>
                        <TableCell>
                          <ObligationStatusBadge status={o.status} />
                        </TableCell>
                        <TableCell className="text-xs">
                          {o.payment_pr_id ? (
                            <a
                              href={obligationInvoiceUrl(data.window_id, o.id)}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-blue-600 hover:underline"
                              title={o.payment_pr_id}
                            >
                              <FileText className="h-3 w-3" />
                              Invoice
                            </a>
                          ) : '—'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      ) : null}
    </main>
  )
}

function SummaryCard({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <Card>
      <CardContent className="pt-4 pb-3 px-4">
        <div
          className="text-2xl font-bold tabular-nums"
          style={warn ? { color: 'var(--destructive)' } : {}}
        >
          {value}
        </div>
        <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
      </CardContent>
    </Card>
  )
}
