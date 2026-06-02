import { Link } from 'react-router-dom'
import { LayoutDashboard, Building2, Scale, ShieldCheck, Activity, Coins, LogOut } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Me } from '@/api'
import type { ActivePage } from '@/App'

const NAV = [
  { id: 'overview',   label: 'Overview',   href: '/',          icon: LayoutDashboard },
  { id: 'pisps',      label: 'PISPs',      href: '/pisps',     icon: Building2 },
  { id: 'disputes',   label: 'Disputes',   href: '/disputes',  icon: Scale },
  { id: 'pki',        label: 'PKI',        href: '/pki',       icon: ShieldCheck },
  { id: 'economics',  label: 'Economics',  href: '/economics', icon: Coins },
  { id: 'network',    label: 'Network',    href: '/network',   icon: Activity },
] as const

interface Props {
  activePage: ActivePage
  me: Me
  onLogout: () => void
}

export function Sidebar({ activePage, me, onLogout }: Props) {
  return (
    <aside className="flex w-56 flex-col border-r border-border bg-sidebar">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-xs font-bold text-primary-foreground">
          SA
        </div>
        <span className="text-sm font-semibold text-sidebar-foreground">Scheme Authority</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 p-2">
        {NAV.map(({ id, label, href, icon: Icon }) => (
          <Link
            key={id}
            to={href}
            className={cn(
              'flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors',
              activePage === id
                ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
                : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground',
            )}
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </Link>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-border p-3">
        <div className="mb-2 truncate px-1 text-xs text-muted-foreground">{me.email}</div>
        <button
          onClick={onLogout}
          className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground transition-colors"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </button>
      </div>
    </aside>
  )
}
