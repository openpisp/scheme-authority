import { useState, useEffect } from 'react'
import { saFetch, type PKIHealth, type CRLStatus } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertTriangle, RefreshCw, RotateCcw } from 'lucide-react'

export function PKI() {
  const [pki, setPki]     = useState<PKIHealth | null>(null)
  const [crl, setCrl]     = useState<CRLStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [rotating, setRotating] = useState(false)
  const [rotateMsg, setRotateMsg] = useState('')

  const load = () => {
    setLoading(true)
    Promise.all([
      saFetch<PKIHealth>('/pki/health'),
      saFetch<CRLStatus>('/crl'),
    ]).then(([p, c]) => { setPki(p); setCrl(c) })
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  const rotateProtocolE = async () => {
    setRotating(true)
    setRotateMsg('')
    try {
      await saFetch('/pki/rotate-sap-key', { method: 'POST' })
      setRotateMsg('SAP key rotated successfully.')
      load()
    } catch (e) {
      setRotateMsg(`Error: ${e}`)
    } finally {
      setRotating(false)
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">PKI</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Certificate health &amp; CRL</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      {pki?.warnings.map((w, i) => (
        <Alert key={i} variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{w}</AlertDescription>
        </Alert>
      ))}

      {loading ? <Skeleton className="h-32 w-full" /> : (
        <>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Certificate expiry</CardTitle></CardHeader>
            <CardContent className="text-sm space-y-3">
              <ExpiryRow label="Intermediate CA"  days={pki?.intermediate_days ?? null} />
              <ExpiryRow label="Protocol E cert"  days={pki?.protocol_e_days ?? null} />
              <div className="flex items-center justify-between pt-1">
                <span className="text-muted-foreground">Protocol E signing</span>
                <Badge variant={pki?.signing_enabled ? 'default' : 'secondary'}>
                  {pki?.signing_enabled ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2 flex flex-row items-center justify-between">
              <CardTitle className="text-sm font-medium">Certificate Revocation List</CardTitle>
            </CardHeader>
            <CardContent className="text-sm space-y-2">
              {crl?.issuer && <Row label="Issuer"       value={crl.issuer} mono />}
              <Row label="Last update"  value={crl ? new Date(crl.last_update).toLocaleString() : '—'} />
              <Row label="Next update"  value={crl ? new Date(crl.next_update).toLocaleString() : '—'} />
              <Row label="CRL number"   value={String(crl?.crl_number ?? '—')} />
              <Row label="Revoked certs" value={String(crl?.entry_count ?? 0)} />
            </CardContent>
          </Card>

          {pki?.signing_enabled && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Key rotation</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">
                  Rotate the Protocol E signing key. PISPs will fetch the new cert from
                  <code className="text-xs bg-muted px-1 rounded">.well-known/psp-certs.json</code> on their next verification.
                </p>
                {rotateMsg && (
                  <p className={`text-sm ${rotateMsg.startsWith('Error') ? 'text-destructive' : 'text-green-600'}`}>
                    {rotateMsg}
                  </p>
                )}
                <Button variant="outline" size="sm" onClick={rotateProtocolE} disabled={rotating}>
                  <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
                  {rotating ? 'Rotating…' : 'Rotate Protocol E key'}
                </Button>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  )
}

function ExpiryRow({ label, days }: { label: string; days: number | null }) {
  if (days === null) return null
  const variant = days <= 7 ? 'destructive' : days <= 30 ? 'secondary' : 'default'
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <Badge variant={variant as 'default' | 'secondary' | 'destructive'}>
        {days}d remaining
      </Badge>
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
