import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { saFetch, type Dispute } from '@/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { ChevronRight } from 'lucide-react'

export function Disputes() {
  const [disputes, setDisputes] = useState<Dispute[]>([])
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    const qs = statusFilter !== 'all' ? `?status=${statusFilter}` : ''
    saFetch<Dispute[]>(`/disputes${qs}`)
      .then(setDisputes)
      .finally(() => setLoading(false))
  }, [statusFilter])

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Disputes</h1>
          <p className="text-sm text-muted-foreground mt-0.5">SA arbitration cases</p>
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="UNDER_REVIEW">Under review</SelectItem>
            <SelectItem value="RESOLVED">Resolved</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">{disputes.length} cases</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="divide-y">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-center gap-4 px-6 py-4">
                  <Skeleton className="h-4 w-48" />
                </div>
              ))}
            </div>
          ) : disputes.length === 0 ? (
            <p className="px-6 py-8 text-center text-sm text-muted-foreground">No disputes.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">SA Dispute ID</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">PISP</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Escalated</th>
                  <th className="px-6 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y">
                {disputes.map(d => (
                  <tr key={d.sa_dispute_id} className="hover:bg-muted/30">
                    <td className="px-6 py-3 mono text-xs">{d.sa_dispute_id.slice(0, 8)}…</td>
                    <td className="px-6 py-3 text-xs text-muted-foreground">{d.pisp_uri}</td>
                    <td className="px-6 py-3">
                      <Badge variant={d.status === 'UNDER_REVIEW' ? 'secondary' : 'default'}>
                        {d.status === 'UNDER_REVIEW' ? 'Under review' : d.verdict ? `Resolved — ${d.verdict}` : 'Resolved'}
                      </Badge>
                    </td>
                    <td className="px-6 py-3 text-muted-foreground">
                      {new Date(d.escalated_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <Link to={`/disputes/${d.sa_dispute_id}`}>
                        <Button variant="ghost" size="sm"><ChevronRight className="h-4 w-4" /></Button>
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
