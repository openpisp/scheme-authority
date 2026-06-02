import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { saFetch, type SAFeePlan, type PISPSummary, type WindowPhases } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { AlertTriangle, Plus, Trash2, ChevronRight, RefreshCw } from 'lucide-react'

// ── helpers ──────────────────────────────────────────────────────────────────

function pence(p: number): string {
  if (p === 0) return '0p'
  if (p < 100) return `${p}p`
  return `£${(p / 100).toFixed(2)}`
}

const MONTH_NAMES = [
  '', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
]

function WindowStatusBadge({ status }: { status: WindowPhases['status'] }) {
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
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${map[status] ?? 'bg-muted text-muted-foreground'}`}>
      {label[status] ?? status}
    </span>
  )
}

// ── Add plan form ─────────────────────────────────────────────────────────────

interface AddPlanFormProps { onSaved: () => void; onCancel: () => void }

function AddPlanForm({ onSaved, onCancel }: AddPlanFormProps) {
  const [form, setForm] = useState({
    name: '', rate: '5', cap_pence: '10', transaction_fee_pence: '0', floor_pence: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))
  const field = 'w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true); setError('')
    try {
      await saFetch('/economics/fee-plans', {
        method: 'POST',
        body: JSON.stringify({
          name:                  form.name.trim(),
          rate:                  parseFloat(form.rate) / 100,
          cap_pence:             parseInt(form.cap_pence),
          transaction_fee_pence: parseInt(form.transaction_fee_pence) || 0,
          floor_pence:           form.floor_pence !== '' ? parseInt(form.floor_pence) : null,
        }),
      })
      onSaved()
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Error') }
    finally { setSubmitting(false) }
  }

  return (
    <Card>
      <CardHeader className="pb-2"><CardTitle className="text-sm">New fee plan</CardTitle></CardHeader>
      <CardContent>
        {error && <Alert variant="destructive" className="mb-3"><AlertTriangle className="h-4 w-4" /><AlertDescription>{error}</AlertDescription></Alert>}
        <form onSubmit={(e) => void handleSubmit(e)} className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          <div className="col-span-2 sm:col-span-5 space-y-1">
            <label className="text-xs font-medium text-muted-foreground">Plan name</label>
            <input className={field} placeholder="e.g. Standard, Premium" value={form.name}
              onChange={set('name')} required />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">Rate (%)</label>
            <input className={field} type="number" min="0" max="100" step="0.01"
              value={form.rate} onChange={set('rate')} required />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">Cap (p)</label>
            <input className={field} type="number" min="0"
              value={form.cap_pence} onChange={set('cap_pence')} required />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">Per-txn fee (p)</label>
            <input className={field} type="number" min="0"
              value={form.transaction_fee_pence} onChange={set('transaction_fee_pence')} />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">Floor (p)</label>
            <input className={field} type="number" min="0" placeholder="none"
              value={form.floor_pence} onChange={set('floor_pence')} />
          </div>
          <div className="flex items-end gap-2">
            <button type="submit" disabled={submitting}
              className="rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors">
              {submitting ? 'Saving…' : 'Save'}
            </button>
            <button type="button" onClick={onCancel}
              className="rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted transition-colors">
              Cancel
            </button>
          </div>
        </form>
        <p className="mt-3 text-xs text-muted-foreground">
          Fee = clamp(floor(amount × rate) + per-txn, floor, cap)
        </p>
      </CardContent>
    </Card>
  )
}

// ── PISP assignment panel ─────────────────────────────────────────────────────

function PISPAssignment({ plans, onChanged }: { plans: SAFeePlan[]; onChanged: () => void }) {
  const [pisps, setPisps]     = useState<PISPSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState<string | null>(null)

  const loadPisps = useCallback(() => {
    setLoading(true)
    saFetch<PISPSummary[]>('/pisps')
      .then(setPisps)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(loadPisps, [loadPisps])

  const handleAssign = async (pispId: string, planId: string | null) => {
    setSaving(pispId)
    try {
      await saFetch(`/pisps/${pispId}/fee-plan`, {
        method: 'POST',
        body: JSON.stringify({ fee_plan_id: planId }),
      })
      loadPisps()
      onChanged()
    } catch (e: unknown) { alert(e instanceof Error ? e.message : 'Error') }
    finally { setSaving(null) }
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold">PISP assignments</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {loading ? (
          <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>PISP</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Current plan</TableHead>
                <TableHead>Assign plan</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pisps.map(p => (
                <TableRow key={p.id}>
                  <TableCell>
                    <div className="font-medium text-sm">{p.name}</div>
                    <div className="text-xs text-muted-foreground font-mono">{p.psp_uri}</div>
                  </TableCell>
                  <TableCell>
                    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
                      p.status === 'active'    ? 'bg-emerald-100 text-emerald-800' :
                      p.status === 'pending'   ? 'bg-amber-100 text-amber-800'    :
                      p.status === 'suspended' ? 'bg-orange-100 text-orange-800'  :
                      'bg-slate-100 text-slate-600'}`}>
                      {p.status}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {p.fee_plan ? p.fee_plan.name : <span className="italic">Scheme default</span>}
                  </TableCell>
                  <TableCell>
                    <select
                      disabled={saving === p.id}
                      value={p.fee_plan?.id ?? ''}
                      onChange={e => void handleAssign(p.id, e.target.value || null)}
                      className="rounded-md border border-input bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
                    >
                      <option value="">Scheme default</option>
                      {plans.filter(pl => !pl.is_default).map(pl => (
                        <option key={pl.id} value={pl.id}>{pl.name}</option>
                      ))}
                    </select>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

// ── Tab: Fee Plans ────────────────────────────────────────────────────────────

function FeePlansTab() {
  const [plans, setPlans]   = useState<SAFeePlan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState('')
  const [adding, setAdding] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    saFetch<SAFeePlan[]>('/economics/fee-plans')
      .then(setPlans)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(load, [load])

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete plan "${name}"? Affected PISPs will revert to the scheme default.`)) return
    try {
      await saFetch(`/economics/fee-plans/${id}`, { method: 'DELETE' })
      load()
    } catch (e: unknown) { alert(e instanceof Error ? e.message : 'Error') }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <p className="text-sm text-muted-foreground">
          Define named fee plans and assign them to PISPs. Unassigned PISPs use the scheme default.
          The assigned plan immediately becomes the default for that PISP's merchants.
        </p>
        <button
          onClick={() => setAdding(a => !a)}
          className="shrink-0 flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <Plus className="h-3.5 w-3.5" /> New plan
        </button>
      </div>

      {error && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertDescription>{error}</AlertDescription></Alert>}

      {adding && <AddPlanForm onSaved={() => { setAdding(false); load() }} onCancel={() => setAdding(false)} />}

      {/* Catalogue */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-semibold">Catalogue</CardTitle></CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="text-right">Rate</TableHead>
                  <TableHead className="text-right">Cap</TableHead>
                  <TableHead className="text-right">Per-txn fee</TableHead>
                  <TableHead className="text-right">Floor</TableHead>
                  <TableHead className="text-right">PISPs</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {plans.map(p => (
                  <TableRow key={p.id} className={p.is_default ? 'bg-muted/40' : ''}>
                    <TableCell className="font-medium text-sm">
                      {p.name}
                      {p.is_default && (
                        <span className="ml-2 inline-flex items-center rounded-full bg-slate-200 px-2 py-0.5 text-[10px] font-semibold text-slate-600 uppercase tracking-wide">
                          default
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-right font-medium">{(p.rate * 100).toFixed(2)}%</TableCell>
                    <TableCell className="text-right text-xs">{pence(p.cap_pence)}</TableCell>
                    <TableCell className="text-right text-xs">{pence(p.transaction_fee_pence)}</TableCell>
                    <TableCell className="text-right text-xs text-muted-foreground">
                      {p.floor_pence != null ? pence(p.floor_pence) : '—'}
                    </TableCell>
                    <TableCell className="text-right text-xs">{p.pisp_count}</TableCell>
                    <TableCell className="text-right">
                      {!p.is_default && (
                        <button onClick={() => void handleDelete(p.id, p.name)}
                          className="rounded p-1 text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* PISP assignments */}
      <PISPAssignment plans={plans} onChanged={load} />
    </div>
  )
}

// ── Tab: Settlement Windows ────────────────────────────────────────────────────

function SettlementWindowsTab() {
  const [windows, setWindows] = useState<WindowPhases[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')

  const load = useCallback(() => {
    setLoading(true)
    saFetch<WindowPhases[]>('/economics/windows')
      .then(setWindows)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(load, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Settlement windows are defined by the SA schedule — all dates are deterministic.
          PISPs submit reports during the <strong>Reporting</strong> and <strong>Reconciling</strong> phases.
        </p>
        <button onClick={load} disabled={loading}
          className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted transition-colors disabled:opacity-50">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertDescription>{error}</AlertDescription></Alert>}

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Window</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Transaction period</TableHead>
                  <TableHead>Reporting closes</TableHead>
                  <TableHead>Payment due</TableHead>
                  <TableHead className="text-right">Reports</TableHead>
                  <TableHead className="text-right">Obligations</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {windows.map(w => (
                  <TableRow key={w.window_id}>
                    <TableCell className="font-medium">
                      {MONTH_NAMES[w.month]} {w.year}
                    </TableCell>
                    <TableCell><WindowStatusBadge status={w.status} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(w.transaction_period_start).toLocaleDateString()} –{' '}
                      {new Date(w.transaction_period_end).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(w.reporting_closes_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(w.payment_due_by).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right text-xs">
                      {w.report_count ?? '—'}
                    </TableCell>
                    <TableCell className="text-right text-xs">
                      {w.obligation_count ?? '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      <Link to={`/economics/windows/${w.window_id}`}
                        className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs font-medium hover:bg-muted transition-colors">
                        View <ChevronRight className="h-3 w-3" />
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

type Tab = 'fee-plans' | 'windows'

const TABS: { id: Tab; label: string }[] = [
  { id: 'fee-plans', label: 'Fee Plans' },
  { id: 'windows',   label: 'Settlement Windows' },
]

export function Economics() {
  const [tab, setTab] = useState<Tab>('fee-plans')

  return (
    <main className="mx-auto max-w-6xl px-6 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Scheme Economics</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Named fee plans, PISP assignments, and inter-PISP settlement windows
        </p>
      </div>

      <div className="flex gap-1 border-b border-border">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={[
              'px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px',
              tab === t.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            ].join(' ')}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'fee-plans' && <FeePlansTab />}
      {tab === 'windows'   && <SettlementWindowsTab />}
    </main>
  )
}
