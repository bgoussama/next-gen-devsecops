// Barre de navigation commune à toutes les pages protégées
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Terminal, Bot, FileCode, History, Activity, Settings, LogOut, Menu, X } from 'lucide-react'
import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'

const NAV_LINKS = [
  { to: '/generator',  label: 'Générateur',  icon: Bot },
  { to: '/editor',     label: 'Éditeur',     icon: FileCode },
  { to: '/history',    label: 'Historique',  icon: History },
  { to: '/monitoring', label: 'Monitoring',  icon: Activity },
  { to: '/settings',   label: 'Paramètres',  icon: Settings },
]

export function Navbar() {
  const { handleLogout } = useAuth()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)

  const onLogout = () => {
    handleLogout()
    navigate('/login')
  }

  return (
    <nav className="sticky top-0 z-50 border-b border-border bg-[oklch(0.14_0.02_260/92%)] backdrop-blur-lg">
      <div className="mx-auto max-w-7xl px-4">
        <div className="flex h-14 items-center justify-between gap-4">

          {/* Logo */}
          <Link to="/dashboard" className="flex items-center gap-2 shrink-0">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
              <Terminal className="h-4 w-4 text-primary" />
            </div>
            <span className="font-bold text-sm hidden sm:block">Next-Gen DevSecOps</span>
          </Link>

          {/* Liens desktop */}
          <div className="hidden md:flex items-center gap-0.5">
            {NAV_LINKS.map(({ to, label, icon: Icon }) => {
              const active = pathname === to
              return (
                <Link
                  key={to}
                  to={to}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                    active
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-secondary'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                </Link>
              )
            })}
          </div>

          {/* Bouton déconnexion */}
          <div className="flex items-center gap-2">
            <button
              onClick={onLogout}
              className="flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
              title="Se déconnecter"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span className="hidden sm:block">Déconnexion</span>
            </button>

            {/* Bouton menu mobile */}
            <button
              className="md:hidden p-1.5 rounded-md text-muted-foreground hover:bg-secondary"
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* Menu mobile déroulant */}
        {mobileOpen && (
          <div className="md:hidden border-t border-border py-2 space-y-0.5">
            {NAV_LINKS.map(({ to, label, icon: Icon }) => (
              <Link
                key={to}
                to={to}
                onClick={() => setMobileOpen(false)}
                className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors ${
                  pathname === to
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary'
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </Link>
            ))}
          </div>
        )}
      </div>
    </nav>
  )
}
