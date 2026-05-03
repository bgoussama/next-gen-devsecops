// Historique des générations — backend + fallback localStorage
import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { History, Search, ExternalLink, CheckCircle, XCircle, Loader2, InboxIcon } from 'lucide-react'
import { Navbar } from '../components/Navbar'
import { apiGetHistory } from '../lib/api'

// Type Pipeline défini localement (non exporté par api.ts)
interface Pipeline {
  id: string
  prompt: string
  pipeline_content?: string
  tokens_used: number
  created_at: string
  status: string
  github_branch_url?: string
}

// ─── Composant principal ───────────────────────────────────────────────────────
export default function HistoryPage() {
  const navigate = useNavigate()
  const [pipelines, setPipelines] = useState<Pipeline[]>([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [search, setSearch]       = useState('')

  // Lire l'historique local depuis localStorage
  const loadLocalHistory = (): Pipeline[] => {
    try {
      return JSON.parse(localStorage.getItem('generationHistory') || '[]')
    } catch {
      return []
    }
  }

  // Charger l'historique — backend en priorité, localStorage en fallback
  useEffect(() => {
    apiGetHistory()
      .then(data => {
        const backendPipelines: Pipeline[] = data.pipelines ?? []
        if (backendPipelines.length > 0) {
          setPipelines(backendPipelines)
        } else {
          // Le backend retourne [] — utiliser l'historique local
          setPipelines(loadLocalHistory())
        }
      })
      .catch(() => {
        // Erreur API — silencieuse, on charge le localStorage
        setPipelines(loadLocalHistory())
      })
      .finally(() => setLoading(false))
  }, [])

  // Filtrage par prompt ou statut
  const filtered = useMemo(() =>
    pipelines.filter(p =>
      p.prompt.toLowerCase().includes(search.toLowerCase()) ||
      p.status.toLowerCase().includes(search.toLowerCase())
    ),
  [pipelines, search])

  // Regroupement par date
  const grouped = useMemo(() => {
    const map = new Map<string, Pipeline[]>()
    for (const p of filtered) {
      const dateKey = new Date(p.created_at).toLocaleDateString('fr-FR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
        year: 'numeric',
      })
      if (!map.has(dateKey)) map.set(dateKey, [])
      map.get(dateKey)!.push(p)
    }
    return Array.from(map.entries())
  }, [filtered])

  // Ouvre le pipeline dans l'éditeur
  const openInEditor = (p: Pipeline) => {
    const gen = {
      id: p.id,
      prompt: p.prompt,
      pipeline_content: p.pipeline_content,
      tokens_used: p.tokens_used,
      created_at: p.created_at,
    }
    localStorage.setItem('lastGeneration', JSON.stringify(gen))
    navigate('/editor')
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="mx-auto max-w-6xl px-4 py-8">
        {/* En-tête */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <History className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Historique</h1>
              <p className="text-sm text-muted-foreground">
                {loading ? 'Chargement...' : `${pipelines.length} génération${pipelines.length > 1 ? 's' : ''}`}
              </p>
            </div>
          </div>

          {/* Barre de recherche */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Rechercher..."
              className="rounded-lg bg-secondary border border-border pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary w-52"
            />
          </div>
        </div>

        {/* État de chargement */}
        {loading && (
          <div className="flex items-center justify-center py-16 gap-3 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" />
            <span className="text-sm">Chargement de l'historique...</span>
          </div>
        )}

        {/* Erreur */}
        {!loading && error && (
          <div className="glass-card rounded-xl p-6 text-center text-destructive text-sm">
            ⚠️ {error}
          </div>
        )}

        {/* Résultats groupés par date */}
        {!loading && !error && (
          <div className="space-y-4">
            {grouped.map(([dateLabel, items]) => (
              <div key={dateLabel} className="glass-card rounded-xl p-4">
                <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 capitalize">
                  {dateLabel}
                </h2>
                <div className="divide-y divide-border/50">
                  {items.map(p => (
                    <div
                      key={p.id}
                      className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 py-3 first:pt-0 last:pb-0 hover:bg-secondary/20 rounded-lg px-2 transition-colors"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        {p.status === 'success' ? (
                          <CheckCircle className="h-4 w-4 text-success mt-0.5 shrink-0" />
                        ) : (
                          <XCircle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                        )}
                        <div className="min-w-0">
                          <p className="text-sm truncate">{p.prompt}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {new Date(p.created_at).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}
                            {p.tokens_used ? ` • ${p.tokens_used.toLocaleString('fr-FR')} tokens` : ''}
                            {' • '}
                            <span className={p.status === 'success' ? 'text-success' : 'text-destructive'}>
                              {p.status}
                            </span>
                          </p>
                        </div>
                      </div>

                      {p.status === 'success' && (
                        <button
                          onClick={() => openInEditor(p)}
                          className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:border-primary/30 hover:bg-secondary transition-colors shrink-0"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                          Ouvrir dans l'éditeur
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {/* Aucun résultat */}
            {grouped.length === 0 && (
              <div className="glass-card rounded-xl p-10 text-center">
                <InboxIcon className="h-10 w-10 text-muted-foreground/40 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">
                  {search ? 'Aucun résultat pour cette recherche.' : 'Aucune génération disponible.'}
                </p>
                {!search && (
                  <p className="text-xs text-muted-foreground/70 mt-2">
                    Les pipelines générés apparaîtront ici automatiquement.
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
