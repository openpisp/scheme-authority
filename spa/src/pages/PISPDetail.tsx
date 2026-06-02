import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { saFetch, type PISPDetail as PISPDetailType } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { ArrowLeft, CheckCircle, PauseCircle, XCircle, AlertTriangle } from 'lucide-react'

type Action = 'approve' | 'suspend' | 'unsuspend' | 'revoke' | null

export function PISPDetail() {
  const { pisp_id } = useParams<{ pisp_id: string }>()
  const [pisp, setPisp]         = useState<PISPDetailType | null>(null)
  const [loading, setLoading]   = useState(true)
  const [action, setAction]     = useState<Action>(null)
  const [reason, setReason]     = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError]       = useState('')

  // edit mode
  const [editName, setEditName]       = useState('')
  const [editBaseUrl, setEditBaseUrl] = useState('')
  const [editBUrl, setEditBUrl]       = useState('')

  const load = () => {
    if (!pisp_id) return
    setLoading(true)
    saFetch<PISPDetailType>(`/pisps/${pisp_id}`)
      .then(p => {
        setPisp(p)
        setEditName(p.name)
        setEditBaseUrl(p.base_url)
        setEditBUrl(p.b_url ?? '')
      })
      .finally(() => setLoading(false))
  }

  useEffect(load, [pisp_id])

  const doAction = async () => {
    if (!pisp || !action) return
    setSubmitting(true)
    setError('')
    try {
      if (action === 'approve') {
        await saFetch(`/pisps/${pisp.id}/approve`, { method: 'POST' })
      } else if (action === 'suspend') {
        await saFetch(`/pisps/${pisp.id}/suspend`, {
          method: 'POST', body: JSON.stringify({ reason }),
        })
      } else if (action === 'unsuspend') {
        await saFetch(`/pisps/${pisp.id}/unsuspend`, { method: 'POST' })
      } else if (action === 'revoke') {
        await saFetch(`/pisps/${pisp.id}/revoke`, {
          method: 'POST', body: JSON.stringify({ reason }),
        })
      }
      setAction(null)
      setReason('')
      load()
    } catch (e) {
      setError(String(e))
    } finally {
      setSubmitting(false)
    }
  }

  const saveEdit = async () => {
    if (!pisp) return
    await saFetch(`/pisps/${pisp.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: editName, base_url: editBaseUrl, b_url: editBUrl || null }),
    })
    load()
  }

  if (loading) return (
    <div className="p-6 space-y-4">
      <Skeleton className="h-6 w-48" />
      <Skeleton className="h-32 w-full" />
    </div>
  )

  if (!pisp) return <div className="p-6 text-sm text-muted-foreground">PISP not found.</div>

  const statusColors: Record<string, string> = {
    active:    'text-green-600',
    pending:   'text-amber-600',
    suspended: 'text-orange-600',
    revoked:   'text-destructive',
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <Link to="/pisps" className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-2">
            <ArrowLeft className="h-3.5 w-3.5" /> PISPs
          </Link>
          <h1 className="text-xl font-semibold">{pisp.name}</h1>
          <p className="text-xs text-muted-foreground mono mt-0.5">{pisp.psp_uri}</p>
        </div>
        <Badge className={`capitalize ${statusColors[pisp.status] ?? ''}`} variant="outline">
          {pisp.status}
        </Badge>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4" /> {error}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex flex-wrap gap-2">
        {pisp.status === 'pending' && (
          <Button size="sm" onClick={() => setAction('approve')}>
            <CheckCircle className="h-3.5 w-3.5 mr-1.5" /> Approve
          </Button>
        )}
        {(pisp.status === 'active' || pisp.status === 'pending') && (
          <Button size="sm" variant="outline" onClick={() => setAction('suspend')}>
            <PauseCircle className="h-3.5 w-3.5 mr-1.5" /> Suspend
          </Button>
        )}
        {pisp.status === 'suspended' && (
          <Button size="sm" variant="outline" onClick={() => setAction('unsuspend')}>
            <CheckCircle className="h-3.5 w-3.5 mr-1.5" /> Lift suspension
          </Button>
        )}
        {pisp.status !== 'revoked' && (
          <Button size="sm" variant="destructive" onClick={() => setAction('revoke')}>
            <XCircle className="h-3.5 w-3.5 mr-1.5" /> Revoke
          </Button>
        )}
      </div>

      {/* Details */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Registration</CardTitle></CardHeader>
        <CardContent className="text-sm space-y-2">
          <Row label="Registered"  value={new Date(pisp.registered_at).toLocaleString()} />
          {pisp.approved_at  && <Row label="Approved"   value={new Date(pisp.approved_at).toLocaleString()} />}
          {pisp.suspended_at && <Row label="Suspended"  value={new Date(pisp.suspended_at).toLocaleString()} />}
          {pisp.suspend_reason && <Row label="Suspend reason" value={pisp.suspend_reason} />}
          {pisp.revoked_at   && <Row label="Revoked"    value={new Date(pisp.revoked_at).toLocaleString()} />}
          {pisp.revoke_reason && <Row label="Revoke reason" value={pisp.revoke_reason} />}
        </CardContent>
      </Card>

      {/* Edit */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Edit</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="name">Name</Label>
            <Input id="name" value={editName} onChange={e => setEditName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="base_url">Base URL</Label>
            <Input id="base_url" value={editBaseUrl} onChange={e => setEditBaseUrl(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="b_url">Protocol B URL</Label>
            <Input id="b_url" value={editBUrl} onChange={e => setEditBUrl(e.target.value)} placeholder="Optional mTLS endpoint" />
          </div>
          <Button size="sm" onClick={saveEdit}>Save changes</Button>
        </CardContent>
      </Card>

      {/* Cert */}
      {pisp.cert && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Certificate</CardTitle></CardHeader>
          <CardContent className="text-sm space-y-2">
            <Row label="Subject"  value={pisp.cert.subject} mono />
            <Row label="Issuer"   value={pisp.cert.issuer} mono />
            <Row label="Valid to" value={new Date(pisp.cert.not_valid_after).toLocaleString()} />
            <Row label="Days remaining" value={String(pisp.cert.days_remaining)} />
            {pisp.cert.psp_uri_san && <Row label="SAN URI" value={pisp.cert.psp_uri_san} mono />}
            <Row label="CRL status" value={pisp.cert.revoked ? 'Revoked' : 'Valid'} />
            <details className="pt-1">
              <summary className="cursor-pointer text-xs text-muted-foreground">Show PEM</summary>
              <pre className="mt-2 overflow-x-auto rounded bg-muted p-3 text-xs mono">{pisp.cert.pem}</pre>
            </details>
          </CardContent>
        </Card>
      )}

      {/* Confirm dialog */}
      <AlertDialog open={action !== null} onOpenChange={open => { if (!open) { setAction(null); setReason('') } }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {action === 'approve' && 'Approve PISP'}
              {action === 'suspend' && 'Suspend PISP'}
              {action === 'unsuspend' && 'Lift suspension'}
              {action === 'revoke' && 'Revoke PISP'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {action === 'approve' && `Approve ${pisp.name} and allow them to participate in the scheme.`}
              {action === 'suspend' && 'Suspend this PISP immediately. They will be removed from the directory but their certificate will not be revoked. This is reversible.'}
              {action === 'unsuspend' && 'Restore this PISP to active status.'}
              {action === 'revoke' && 'Permanently revoke this PISP. Their certificate will be added to the CRL. This cannot be undone.'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          {(action === 'suspend' || action === 'revoke') && (
            <div className="space-y-1 px-1">
              <Label>Reason {action === 'revoke' ? '(required)' : '(optional)'}</Label>
              <Textarea
                value={reason}
                onChange={e => setReason(e.target.value)}
                placeholder="Enter reason…"
                rows={3}
              />
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={doAction}
              disabled={submitting || (action === 'revoke' && !reason.trim())}
              className={action === 'revoke' ? 'bg-destructive hover:bg-destructive/90' : ''}
            >
              {submitting ? 'Working…' : 'Confirm'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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
