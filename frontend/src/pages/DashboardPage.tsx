// Dashboard principal — métriques, graphiques, état des services
import { useEffect, useState } from 'react'
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip } from 'recharts'
import { Activity, GitBranch, Cpu, CheckCircle, Clock, Zap } from 'lucide-react'
import { Navbar } from '../components/Navbar'
import { apiGetHistory, apiHealthCheck } from '../lib/api'

// ─── Données mock pour les graphiques (Phase 9 branchera Prometheus) ──────────
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
  { time: '04h', value: 95 },
  { time: '08h', value: 210 },
  { time: '12h', value: 185 },
  { time: '16h', value: 245 },
  { time: '20h', value: 160 },
  { time: '24h', value: 130 },
]

// ─── Statuts des services ──────────────────────────────────────────────────────
interface ServiceStatus {
  name: string
  status: 'healthy' | 'warning' | 'error' | 'loading'
  description: string
}

const STATUS_DOT: Record<string, string> = {
  healthy: 'bg-success',
  warning: 'bg-warning',
  error:   'bg-destructive',
  loading: 'bg-muted-foreground',
}
const STATUS_TEXT: Record<string, string> = {
  healthy: 'text-success',
  warning: 'text-warning',
  error:   'text-destructive',
  loading: 'text-muted-foreground',
}

// ─── Carte KPI ────────────────────────────────────────────────────────────────
function KPICard({ icon: Icon, label, value, sub, highlight = false }: {
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
export default function DashboardPage() {
  const [metrics, setMetrics] = useState({
    pipelines: 0,
    tokens: 0,
    successRate: 100,
    avgTime: 3.2,
  })
  const [services, setServices] = useState<ServiceStatus[]>([
    { name: 'API Gateway',   status: 'loading', description: 'Vérification...' },
    { name: 'Auth Service',  status: 'loading', description: 'Vérification...' },
    { name: 'Redis Cache',   status: 'healthy', description: 'Opérationnel' },
    { name: 'Groq API',      status: 'healthy', description: 'Opérationnel' },
  ])

  useEffect(() => {
    // Charger les métriques réelles depuis l'historique
    apiGetHistory()
      .then(({ pipelines }: { pipelines: { tokens_used?: number; status: string }[] }) => {
        const total    = pipelines.length
        const tokens   = pipelines.reduce((s, p) => s + (p.tokens_used ?? 0), 0)
        const success  = pipelines.filter(p => p.status === 'success').length
        setMetrics({
          pipelines: total,
          tokens,
          successRate: total > 0 ? Math.round((success / total) * 100) : 100,
          avgTime: 3.2,
        })
      })
      .catch(() => {})

    // Vérifier la santé du backend pour API Gateway et Auth Service
    apiHealthCheck()
      .then(isHealthy => {
        const status = isHealthy ? 'healthy' : 'error'
        setServices(prev => prev.map(svc =>
          svc.name === 'API Gateway' || svc.name === 'Auth Service'
            ? { ...svc, status, description: status === 'healthy' ? 'Opérationnel' : 'Indisponible' }
            : svc
        ))
      })
      .catch(() => {
        setServices(prev => prev.map(svc =>
          svc.name === 'API Gateway' || svc.name === 'Auth Service'
            ? { ...svc, status: 'error', description: 'Indisponible' }
            : svc
        ))
      })
  }, [])

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="mx-auto max-w-7xl px-4 py-8">
        {/* En-tête */}
        <div className="flex items-center gap-3 mb-8">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
            <Activity className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Dashboard & Observabilité</h1>
            <p className="text-sm text-muted-foreground">Monitoring temps réel de votre infrastructure</p>
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
          <KPICard
            icon={GitBranch}
            label="Pipelines générés"
            value={metrics.pipelines.toString()}
            sub="Depuis la création du compte"
            highlight
          />
          <KPICard
            icon={Zap}
            label="Tokens utilisés"
            value={metrics.tokens.toLocaleString('fr-FR')}
            sub="Consommation totale LLM"
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
            sub="Par génération (mock)"
          />
        </div>

        {/* Graphiques */}
        <div className="grid gap-6 lg:grid-cols-2 mb-8">
          {/* Bar chart — déploiements */}
          <div className="glass-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Cpu className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Déploiements cette semaine</h3>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={DEPLOYMENTS_DATA}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.02 260)" />
                <XAxis dataKey="date" tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} />
                <YAxis tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    background: 'oklch(0.16 0.02 260)',
                    border: '1px solid oklch(0.25 0.02 260)',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
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
                <XAxis dataKey="time" tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} />
                <YAxis tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    background: 'oklch(0.16 0.02 260)',
                    border: '1px solid oklch(0.25 0.02 260)',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="value"
                  name="Latence"
                  stroke="oklch(0.78 0.18 195)"
                  strokeWidth={2}
                  dot={{ fill: 'oklch(0.78 0.18 195)', r: 4 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* État des services */}
        <div className="glass-card rounded-xl p-5">
          <h3 className="text-sm font-semibold mb-4">État des services</h3>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {services.map(svc => (
              <div key={svc.name} className="flex items-center gap-3 rounded-lg border border-border p-3 bg-secondary/30">
                <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${STATUS_DOT[svc.status]} ${svc.status !== 'healthy' && svc.status !== 'loading' ? 'animate-pulse-glow' : ''}`} />
                <div>
                  <p className="text-sm font-medium">{svc.name}</p>
                  <p className={`text-xs capitalize ${STATUS_TEXT[svc.status]}`}>
                    {svc.status === 'loading' ? 'Vérification...' : svc.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  )
}
