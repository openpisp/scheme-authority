import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { saFetch, type Dispute } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { ArrowLeft } from 'lucide-react'

export function DisputeDetail() {
  const { sa_dispute_id } = useParams<{ sa_dispute_id: string }>()
  const [dispute, setDispute]   = useState<Dispute | null>(null)
  const [loading, setLoading]   = useState(true)
  const [verdict, setVerdict]   = useState<'UPHELD' | 'REJECTED'>('REJECTED')
  const [rationale, setRationale] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError]       = useState('')

  const load = () => {
    if (!sa_dispute_id) return
    setLoading(true)
    saFetch<Dispute>(`/disputes/${sa_dispute_id}`)
      .then(setDispute)
      .finally(() => setLoading(false))
  }
  useEffect(load, [sa_dispute_id])

  const resolve = async () => {
    if (!dispute || !rationale.trim()) return
    setSubmitting(true)
    setError('')
    try {
      await saFetch(`/disputes/${dispute.sa_dispute_id}/resolve`, {
        method: 'POST',
        body: JSON.stringify({ verdict, rationale }),
      })
      load()
    } catch (e) {
      setError(String(e))
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) return <div className="p-6"><Skeleton className="h-48 w-full" /></div>
  if (!dispute) return <div className="p-6 text-sm text-muted-foreground">Dispute not found.</div>

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div>
        <Link to="/disputes" className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-2">
          <ArrowLeft className="h-3.5 w-3.5" /> Disputes
        </Link>
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-semibold">Dispute</h1>
          <Badge variant={dispute.status === 'UNDER_REVIEW' ? 'secondary' : 'default'}>
            {dispute.status === 'UNDER_REVIEW' ? 'Under review' : 'Resolved'}
          </Badge>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Details</CardTitle></CardHeader>
        <CardContent className="text-sm space-y-2">
          <Row label="SA Dispute ID"  value={dispute.sa_dispute_id} mono />
          <Row label="Dispute ID"     value={dispute.dispute_id} mono />
          <Row label="Escalated by"   value={dispute.pisp_uri} />
          <Row label="Payer PISP"     value={dispute.payer_pisp_uri ?? '—'} />
          <Row label="Requester PISP" value={dispute.requester_pisp_uri ?? '—'} />
          <Row label="Escalated at"   value={new Date(dispute.escalated_at).toLocaleString()} />
          {dispute.evidence_summary && (
            <div>
              <div className="text-muted-foreground mb-1">Evidence summary</div>
              <div className="rounded bg-muted p-2 text-xs">{dispute.evidence_summary}</div>
            </div>
          )}
        </CardContent>
      </Card>

      {dispute.status === 'RESOLVED' && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Verdict</CardTitle></CardHeader>
          <CardContent className="text-sm space-y-2">
            <Row label="Verdict"    value={dispute.verdict ?? '—'} />
            <Row label="Resolved"   value={dispute.resolved_at ? new Date(dispute.resolved_at).toLocaleString() : '—'} />
            {dispute.rationale && <div>
              <div className="text-muted-foreground mb-1">Rationale</div>
              <div className="rounded bg-muted p-2 text-xs">{dispute.rationale}</div>
            </div>}
          </CardContent>
        </Card>
      )}

      {dispute.status === 'UNDER_REVIEW' && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Issue verdict</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label>Verdict</Label>
              <Select value={verdict} onValueChange={v => setVerdict(v as 'UPHELD' | 'REJECTED')}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="UPHELD">UPHELD — rule in favour of payer</SelectItem>
                  <SelectItem value="REJECTED">REJECTED — rule in favour of requester</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Rationale <span className="text-muted-foreground">(required)</span></Label>
              <Textarea
                value={rationale}
                onChange={e => setRationale(e.target.value)}
                placeholder="Explain the SA's reasoning…"
                rows={4}
              />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button onClick={resolve} disabled={submitting || !rationale.trim()}>
              {submitting ? 'Issuing…' : 'Issue verdict'}
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className={`text-right break-all ${mono ? 'mono text-xs' : ''}`}>{value}</span>
    </div>
  )
}
