// Page de connexion — dark theme cyber
import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Terminal, Loader2, AlertCircle, ChevronRight, Shield } from 'lucide-react'
import { apiLogin } from '../lib/api'
import { useAuth } from '../hooks/useAuth'

export default function LoginPage() {
  const navigate = useNavigate()
  const { handleLogin } = useAuth()

  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await apiLogin(email, password)
      localStorage.setItem('email', email)
      handleLogin(data.access_token, data.role, data.user_id)
      navigate('/generator')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur de connexion')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      {/* Grille décorative en arrière-plan */}
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_top,oklch(0.78_0.18_195/8%)_0%,transparent_60%)] pointer-events-none" />

      <div className="w-full max-w-md relative">
        {/* Logo + titre */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 border border-primary/20">
              <Terminal className="h-8 w-8 text-primary" />
            </div>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Next-Gen DevSecOps</h1>
          <p className="text-sm text-muted-foreground mt-1">Plateforme de génération de pipelines CI/CD par IA</p>
        </div>

        {/* Formulaire de connexion */}
        <div className="glass-card rounded-2xl p-6">
          <div className="flex items-center gap-2 mb-5">
            <Shield className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">Connexion sécurisée</h2>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs text-muted-foreground block mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="email@nextgen.local"
                required
                className="w-full rounded-lg bg-secondary border border-border px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
              />
            </div>

            <div>
              <label className="text-xs text-muted-foreground block mb-1.5">Mot de passe</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full rounded-lg bg-secondary border border-border px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
              />
            </div>

            {/* Message d'erreur */}
            {error && (
              <div className="flex items-center gap-2 rounded-lg bg-destructive/10 border border-destructive/20 px-3 py-2.5">
                <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
                <p className="text-xs text-destructive">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50 hover:bg-primary/90 transition-colors glow-cyan mt-2"
            >
              {loading ? (
                <><Loader2 className="h-4 w-4 animate-spin" /> Connexion en cours...</>
              ) : (
                <>Se connecter <ChevronRight className="h-4 w-4" /></>
              )}
            </button>
          </form>
        </div>

      </div>
    </div>
  )
}
