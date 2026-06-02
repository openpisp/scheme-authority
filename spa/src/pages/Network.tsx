import { useState, useEffect } from 'react'
import { saFetch, type NetworkStats } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Activity } from 'lucide-react'

export function Network() {
  const [stats, setStats] = useState<NetworkStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    saFetch<NetworkStats>('/network/stats')
      .then(setStats)
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div>
        <h1 className="text-xl font-semibold">Network</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Scheme-wide statistics — S6</p>
      </div>

      {loading ? <Skeleton className="h-48 w-full" /> : (
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Activity className="h-4 w-4" /> PISP breakdown
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm space-y-2">
              {stats && Object.entries(stats.pisps).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between">
                  <span className="text-muted-foreground capitalize">{k}</span>
                  <span className="font-medium tabular-nums">{v}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Disputes</CardTitle>
            </CardHeader>
            <CardContent className="text-sm space-y-2">
              {stats && Object.entries(stats.disputes).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between">
                  <span className="text-muted-foreground capitalize">{k.replace('_', ' ')}</span>
                  <span className="font-medium tabular-nums">{v}</span>
                </div>
              ))}
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">CRL entries</span>
                <span className="font-medium tabular-nums">{stats?.crl_entries}</span>
              </div>
            </CardContent>
          </Card>

          <p className="text-xs text-muted-foreground">
            Per-PISP volume and uptime reporting (S6 full) will be added once PISPs push periodic stats via the scheme heartbeat endpoint.
          </p>
        </div>
      )}
    </div>
  )
}
