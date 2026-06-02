import { useState, useEffect } from 'react'
import { saFetch, type NetworkStats, type PKIHealth } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Building2, Scale, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react'

export function Overview() {
  const [stats, setStats]   = useState<NetworkStats | null>(null)
  const [pki, setPki]       = useState<PKIHealth | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      saFetch<NetworkStats>('/network/stats'),
      saFetch<PKIHealth>('/pki/health'),
    ]).then(([s, p]) => { setStats(s); setPki(p) })
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Overview</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Scheme network at a glance</p>
      </div>

      {/* PKI warnings */}
      {pki?.warnings.map((w, i) => (
        <Alert key={i} variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{w}</AlertDescription>
        </Alert>
      ))}

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {loading ? Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}><CardContent className="pt-6"><Skeleton className="h-8 w-16" /></CardContent></Card>
        )) : (<>
          <StatCard title="Active PISPs"    value={stats?.pisps.active ?? 0}    icon={<Building2 className="h-4 w-4 text-green-600" />} />
          <StatCard title="Pending"         value={stats?.pisps.pending ?? 0}   icon={<Building2 className="h-4 w-4 text-amber-500" />} />
          <StatCard title="Suspended"       value={stats?.pisps.suspended ?? 0} icon={<ShieldAlert className="h-4 w-4 text-orange-500" />} />
          <StatCard title="Open Disputes"   value={stats?.disputes.under_review ?? 0} icon={<Scale className="h-4 w-4 text-blue-500" />} />
        </>)}
      </div>

      {/* PKI health */}
      {pki && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" /> PKI Health
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <PKIRow label="Intermediate CA"  days={pki.intermediate_days} />
            <PKIRow label="Protocol E cert"  days={pki.protocol_e_days} />
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Protocol E signing</span>
              <Badge variant={pki.signing_enabled ? 'default' : 'secondary'}>
                {pki.signing_enabled ? 'Enabled' : 'Disabled'}
              </Badge>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function StatCard({ title, value, icon }: { title: string; value: number; icon: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-1 pt-4 px-4">
        <CardTitle className="text-xs font-medium text-muted-foreground">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent className="px-4 pb-4">
        <div className="text-2xl font-bold">{value}</div>
      </CardContent>
    </Card>
  )
}

function PKIRow({ label, days }: { label: string; days: number | null }) {
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
