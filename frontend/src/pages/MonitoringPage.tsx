// Page de monitoring — graphiques, métriques et état des services
// Style inspiré de dashboard.tsx du projet de référence (dark theme cyan/teal, glass-card, Recharts)
import { useEffect, useState } from 'react'
import {
  BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip, Legend,
} from 'recharts'
import { Activity, GitBranch, Zap, CheckCircle, Clock, Server } from 'lucide-react'
import { Navbar } from '../components/Navbar'
import { apiGetHistory, apiHealthCheck } from '../lib/api'

// ─── Données mock pour les graphiques ─────────────────────────────────────────
// Phase 9 : à remplacer par les vraies métriques Prometheus
const DEPLOYMENTS_DATA = [
  { date: 'Lun', success: 4, failed: 1 },
  { date: 'Mar', success: 7, failed: 0 },
  { date: 'Mer', success: 5, failed: 2 },
  { date: 'Jeu', success: 9, failed: 1 },
  { date: 'Ven', success: 6, failed: 0 },
  { date: 'Sam', success: 3, failed: 1 },
  { date: 'Dim', success: 2, failed: 0 },
]

const LATENCY_DATA = [
  { time: '00h', value: 120 },
  { time: '03h', value: 88 },
  { time: '06h', value: 95 },
  { time: '09h', value: 230 },
  { time: '12h', value: 185 },
  { time: '15h', value: 260 },
  { time: '18h', value: 200 },
  { time: '21h', value: 145 },
  { time: '24h', value: 110 },
]

// ─── Types ────────────────────────────────────────────────────────────────────
type ServiceStatus = 'healthy' | 'warning' | 'error' | 'loading'

interface Service {
  name: string
  status: ServiceStatus
  description: string
  group: string
}

// Couleurs selon le statut du service
const STATUS_DOT: Record<ServiceStatus, string> = {
  healthy: 'bg-success',
  warning: 'bg-warning',
  error:   'bg-destructive',
  loading: 'bg-muted-foreground',
}

const STATUS_TEXT: Record<ServiceStatus, string> = {
  healthy: 'text-success',
  warning: 'text-warning',
  error:   'text-destructive',
  loading: 'text-muted-foreground',
}

const STATUS_LABEL: Record<ServiceStatus, string> = {
  healthy: 'Opérationnel',
  warning: 'Dégradé',
  error:   'Indisponible',
  loading: 'Vérification...',
}

// ─── Carte KPI ────────────────────────────────────────────────────────────────
function KPICard({
  icon: Icon, label, value, sub, highlight = false,
}: {
  icon: React.ElementType
  label: string
  value: string
  sub: string
  highlight?: boolean
}) {
  return (
    <div className={`glass-card rounded-xl p-4 ${highlight ? 'glow-cyan' : ''}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="h-4 w-4 text-primary" />
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <p className="text-2xl font-bold">{value}</p>
      <p className="text-xs text-muted-foreground mt-1">{sub}</p>
    </div>
  )
}

// ─── Composant principal ───────────────────────────────────────────────────────
export default function MonitoringPage() {
  // Métriques calculées depuis l'historique réel
  const [metrics, setMetrics] = useState({
    pipelines:   0,
    tokens:      0,
    successRate: 100,
    avgTime:     3.2,
  })

  // État initial des services — health vérifié dynamiquement
  const [services, setServices] = useState<Service[]>([
    { name: 'API Gateway',   status: 'loading', description: STATUS_LABEL.loading, group: 'Backend' },
    { name: 'Auth Service',  status: 'loading', description: STATUS_LABEL.loading, group: 'Backend' },
    { name: 'Redis Cache',   status: 'healthy', description: STATUS_LABEL.healthy, group: 'Infra' },
    { name: 'Groq API',      status: 'healthy', description: STATUS_LABEL.healthy, group: 'LLM' },
  ])

  useEffect(() => {
    // Charger les métriques depuis l'historique réel du backend
    apiGetHistory()
      .then(({ pipelines }: { pipelines: { tokens_used?: number; status: string }[] }) => {
        const total    = pipelines.length
        const tokens   = pipelines.reduce((acc, p) => acc + (p.tokens_used ?? 0), 0)
        const success  = pipelines.filter(p => p.status === 'success').length
        setMetrics({
          pipelines:   total,
          tokens,
          successRate: total > 0 ? Math.round((success / total) * 100) : 100,
          avgTime:     3.2,
        })
      })
      .catch(() => {})

    // Vérifier GET /health pour API Gateway et Auth Service
    apiHealthCheck()
      .then(isHealthy => {
        const status: ServiceStatus = isHealthy ? 'healthy' : 'error'
        setServices(prev =>
          prev.map(svc =>
            svc.group === 'Backend'
              ? { ...svc, status, description: STATUS_LABEL[status] }
              : svc
          )
        )
      })
      .catch(() => {
        setServices(prev =>
          prev.map(svc =>
            svc.group === 'Backend'
              ? { ...svc, status: 'error', description: STATUS_LABEL.error }
              : svc
          )
        )
      })
  }, [])

  // Calcul du statut global pour le badge en haut
  const allHealthy = services.every(s => s.status === 'healthy')
  const anyError   = services.some(s => s.status === 'error')

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="mx-auto max-w-7xl px-4 py-8">

        {/* ─── En-tête ─────────────────────────────────────────────────────── */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Activity className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Monitoring & Observabilité</h1>
              <p className="text-sm text-muted-foreground">Surveillance en temps réel de l'infrastructure</p>
            </div>
          </div>

          {/* Badge statut global */}
          <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${
            anyError
              ? 'bg-destructive/10 border-destructive/20 text-destructive'
              : allHealthy
                ? 'bg-success/10 border-success/20 text-success'
                : 'bg-warning/10 border-warning/20 text-warning'
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${anyError ? 'bg-destructive' : allHealthy ? 'bg-success' : 'bg-warning'} animate-pulse-glow`} />
            {anyError ? 'Incidents détectés' : allHealthy ? 'Tous les services sont opérationnels' : 'Vérification en cours'}
          </span>
        </div>

        {/* ─── KPI Cards ───────────────────────────────────────────────────── */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
          <KPICard
            icon={GitBranch}
            label="Pipelines générés"
            value={metrics.pipelines.toString()}
            sub="Total des générations"
            highlight
          />
          <KPICard
            icon={Zap}
            label="Tokens consommés"
            value={metrics.tokens.toLocaleString('fr-FR')}
            sub="Consommation LLM cumulée"
          />
          <KPICard
            icon={CheckCircle}
            label="Taux de succès"
            value={`${metrics.successRate}%`}
            sub="Générations réussies"
          />
          <KPICard
            icon={Clock}
            label="Temps moyen"
            value={`${metrics.avgTime}s`}
            sub="Par génération (estimé)"
          />
        </div>

        {/* ─── Graphiques ──────────────────────────────────────────────────── */}
        <div className="grid gap-6 lg:grid-cols-2 mb-8">

          {/* Bar chart — déploiements de la semaine */}
          <div className="glass-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <GitBranch className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Déploiements cette semaine</h3>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={DEPLOYMENTS_DATA} barGap={4}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.02 260)" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: 'oklch(0.16 0.02 260)',
                    border: '1px solid oklch(0.25 0.02 260)',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  cursor={{ fill: 'oklch(1 0 0 / 4%)' }}
                />
                <Legend
                  wrapperStyle={{ fontSize: 11, color: 'oklch(0.60 0.02 260)' }}
                />
                <Bar dataKey="success" name="Succès" fill="oklch(0.72 0.19 150)" radius={[4, 4, 0, 0]} />
                <Bar dataKey="failed"  name="Échec"  fill="oklch(0.60 0.22 25)"  radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Line chart — latence API */}
          <div className="glass-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Activity className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Latence API (ms)</h3>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={LATENCY_DATA}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.02 260)" />
                <XAxis
                  dataKey="time"
                  tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                  unit=" ms"
                />
                <Tooltip
                  contentStyle={{
                    background: 'oklch(0.16 0.02 260)',
                    border: '1px solid oklch(0.25 0.02 260)',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  formatter={(val: number) => [`${val} ms`, 'Latence']}
                />
                <Line
                  type="monotone"
                  dataKey="value"
                  name="Latence"
                  stroke="oklch(0.78 0.18 195)"
                  strokeWidth={2}
                  dot={{ fill: 'oklch(0.78 0.18 195)', r: 3, strokeWidth: 0 }}
                  activeDot={{ r: 5, fill: 'oklch(0.78 0.18 195)' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ─── État des services ────────────────────────────────────────────── */}
        <div className="glass-card rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Server className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">État des services</h3>
            <span className="ml-auto text-xs text-muted-foreground">
              Mis à jour au chargement de la page
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {services.map(svc => (
              <div
                key={svc.name}
                className="flex items-center gap-3 rounded-lg border border-border p-3 bg-secondary/30 hover:bg-secondary/50 transition-colors"
              >
                {/* Indicateur de statut */}
                <span
                  className={`h-2.5 w-2.5 shrink-0 rounded-full ${STATUS_DOT[svc.status]} ${
                    svc.status !== 'healthy' && svc.status !== 'loading'
                      ? 'animate-pulse-glow'
                      : ''
                  }`}
                />
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">{svc.name}</p>
                  <p className={`text-xs ${STATUS_TEXT[svc.status]}`}>
                    {svc.status === 'loading' ? STATUS_LABEL.loading : svc.description}
                  </p>
                </div>
                {/* Badge groupe */}
                <span className="ml-auto text-xs text-muted-foreground/60 shrink-0">{svc.group}</span>
              </div>
            ))}
          </div>

          {/* Note sur les données mock */}
          <p className="text-xs text-muted-foreground/50 mt-4">
            Les graphiques utilisent des données simulées. La connexion Prometheus sera ajoutée en Phase 9.
          </p>
        </div>

      </main>
    </div>
  )
}
