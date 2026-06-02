import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { saFetch, type Me } from './api'
import { LoginPage } from './components/LoginPage'
import { Sidebar } from './components/Sidebar'
import { Overview } from './pages/Overview'
import { PISPs } from './pages/PISPs'
import { PISPDetail } from './pages/PISPDetail'
import { Disputes } from './pages/Disputes'
import { DisputeDetail } from './pages/DisputeDetail'
import { PKI } from './pages/PKI'
import { Economics } from './pages/Economics'
import { WindowDetail } from './pages/WindowDetail'
import { Network } from './pages/Network'

export type ActivePage = 'overview' | 'pisps' | 'disputes' | 'pki' | 'economics' | 'network'

function useActivePage(): ActivePage {
  const { pathname } = useLocation()
  if (pathname.startsWith('/pisps'))     return 'pisps'
  if (pathname.startsWith('/disputes'))  return 'disputes'
  if (pathname.startsWith('/pki'))       return 'pki'
  if (pathname.startsWith('/economics')) return 'economics'
  if (pathname.startsWith('/network'))   return 'network'
  return 'overview'
}

function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const activePage = useActivePage()
  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar activePage={activePage} me={me} onLogout={onLogout} />
      <main className="flex-1 min-w-0 overflow-auto">
        <Routes>
          <Route path="/"                            element={<Overview />} />
          <Route path="/pisps"                       element={<PISPs />} />
          <Route path="/pisps/:pisp_id"              element={<PISPDetail />} />
          <Route path="/disputes"                    element={<Disputes />} />
          <Route path="/disputes/:sa_dispute_id"     element={<DisputeDetail />} />
          <Route path="/pki"                         element={<PKI />} />
          <Route path="/economics"                   element={<Economics />} />
          <Route path="/economics/windows/:window_id" element={<WindowDetail />} />
          <Route path="/network"                     element={<Network />} />
          <Route path="*"                            element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [loading, setLoading] = useState(true)

  const checkAuth = () => {
    saFetch<Me>('/me')
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    checkAuth()
    const handler = () => { setMe(null); setLoading(false) }
    window.addEventListener('sa:unauthorized', handler)
    return () => window.removeEventListener('sa:unauthorized', handler)
  }, [])

  const handleLogout = async () => {
    await fetch('/auth/logout-api', { credentials: 'include' })
    setMe(null)
  }

  if (loading) return (
    <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
      Loading…
    </div>
  )

  if (!me) return <LoginPage onLogin={setMe} />

  return (
    <BrowserRouter basename="/app">
      <Shell me={me} onLogout={handleLogout} />
    </BrowserRouter>
  )
}
