// Paramètres — profil, webhook Jenkins
import { useState } from 'react'
import { Settings, User, Webhook, Save, Check } from 'lucide-react'
import { Navbar } from '../components/Navbar'
import { tokenService } from '../lib/api'

export default function SettingsPage() {
  // Lecture des données depuis localStorage
  const email  = localStorage.getItem('email') ?? ''
  const role   = tokenService.getRole()   ?? ''
  const userId = tokenService.getUserId() ?? ''

  // Paramètre persisté en localStorage
  const [webhookUrl, setWebhookUrl] = useState(() => localStorage.getItem('jenkins_webhook') ?? '')
  const [saved, setSaved]         = useState(false)

  const handleSave = () => {
    localStorage.setItem('jenkins_webhook', webhookUrl)
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  const ROLE_STYLE: Record<string, string> = {
    admin:  'text-red-400 bg-red-400/10 border border-red-400/20',
    devops: 'text-cyan-400 bg-cyan-400/10 border border-cyan-400/20',
    dev:    'text-green-400 bg-green-400/10 border border-green-400/20',
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="mx-auto max-w-3xl px-4 py-8">
        {/* En-tête */}
        <div className="flex items-center gap-3 mb-8">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
            <Settings className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Paramètres</h1>
            <p className="text-sm text-muted-foreground">Configuration des intégrations et préférences</p>
          </div>
        </div>

        <div className="space-y-5">
          {/* ─── Profil utilisateur ─────────────────────────────────────────── */}
          <div className="glass-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <User className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Profil</h3>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-border">
                <span className="text-xs text-muted-foreground">Email</span>
                <span className="text-sm font-mono">{email || '—'}</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-border">
                <span className="text-xs text-muted-foreground">Rôle</span>
                <span className={`text-xs font-semibold px-2.5 py-0.5 rounded-full ${ROLE_STYLE[role] ?? 'text-primary bg-primary/10 border border-primary/20'}`}>
                  {role || '—'}
                </span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-xs text-muted-foreground">ID utilisateur</span>
                <span className="text-xs font-mono text-muted-foreground">{userId || '—'}</span>
              </div>
            </div>
          </div>

          {/* ─── Webhook Jenkins ─────────────────────────────────────────────── */}
          <div className="glass-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-3">
              <Webhook className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Webhook Jenkins</h3>
            </div>
            <p className="text-xs text-muted-foreground mb-3">
              URL du webhook pour déclencher les pipelines Jenkins automatiquement.
            </p>
            <input
              value={webhookUrl}
              onChange={e => setWebhookUrl(e.target.value)}
              placeholder="https://jenkins.example.com/generic-webhook-trigger/invoke"
              className="w-full rounded-lg bg-secondary border border-border px-3 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
            />
          </div>

          {/* ─── Note sur les clés API ──────────────────────────────────────── */}
          <div className="rounded-xl border border-border/50 p-4 bg-secondary/20">
            <p className="text-xs text-muted-foreground">
              <span className="text-primary font-medium">ℹ️ Clés API :</span> Les clés GROQ et Gemini sont gérées côté backend via les variables d'environnement. Vous n'avez pas besoin de les configurer ici.
            </p>
          </div>

          {/* ─── Bouton sauvegarder ────────────────────────────────────────── */}
          <button
            onClick={handleSave}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground hover:bg-primary/90 transition-colors glow-cyan"
          >
            {saved
              ? <><Check className="h-4 w-4" /> Sauvegardé !</>
              : <><Save className="h-4 w-4" /> Sauvegarder</>
            }
          </button>
        </div>
      </main>
    </div>
  )
}
