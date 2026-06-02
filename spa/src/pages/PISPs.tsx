import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { saFetch, type PISPSummary, type PISPStatus } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { ChevronRight, RefreshCw } from 'lucide-react'

function statusBadge(s: PISPStatus) {
  const variants: Record<PISPStatus, 'default' | 'secondary' | 'destructive' | 'outline'> = {
    active:    'default',
    pending:   'secondary',
    suspended: 'outline',
    revoked:   'destructive',
  }
  return <Badge variant={variants[s]} className="capitalize">{s}</Badge>
}

export function PISPs() {
  const [pisps, setPisps] = useState<PISPSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')

  const load = () => {
    setLoading(true)
    saFetch<PISPSummary[]>('/pisps')
      .then(setPisps)
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">PISPs</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Registered payment institutions</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
          Refresh
        </Button>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">{pisps.length} total</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="divide-y">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="flex items-center gap-4 px-6 py-4">
                  <Skeleton className="h-4 w-48" />
                  <Skeleton className="h-5 w-16 ml-auto" />
                </div>
              ))}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Name / URI</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Fee Plan</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Cert</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Registered</th>
                  <th className="px-6 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y">
                {pisps.map(p => (
                  <tr key={p.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-6 py-3">
                      <div className="font-medium">{p.name}</div>
                      <div className="text-xs text-muted-foreground mono">{p.psp_uri}</div>
                    </td>
                    <td className="px-6 py-3">{statusBadge(p.status)}</td>
                    <td className="px-6 py-3 text-xs text-muted-foreground">
                      {p.fee_plan
                        ? <span className="font-medium text-foreground">{p.fee_plan.name}</span>
                        : <span className="italic">Scheme default</span>}
                    </td>
                    <td className="px-6 py-3">
                      {p.cert_days !== null ? (
                        <span className={p.cert_days <= 30 ? 'text-amber-600' : 'text-muted-foreground'}>
                          {p.cert_days}d
                        </span>
                      ) : '—'}
                    </td>
                    <td className="px-6 py-3 text-muted-foreground">
                      {new Date(p.registered_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <Link to={`/pisps/${p.id}`}>
                        <Button variant="ghost" size="sm">
                          <ChevronRight className="h-4 w-4" />
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
