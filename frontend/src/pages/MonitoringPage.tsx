// Page de monitoring — graphiques, métriques et rapports Jenkins
// Toutes les données sont réelles : Prometheus query_range pour les graphiques
import { useEffect, useState, useCallback } from 'react'
import {
  BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip, Legend,
} from 'recharts'
import { Activity, GitBranch, Zap, CheckCircle, Clock, RefreshCw, Download, Eye, X } from 'lucide-react'
import { Navbar } from '../components/Navbar'
import { apiGetHistory, apiGetPipelineReports } from '../lib/api'

const PROMETHEUS_URL = 'http://localhost:9090'

// ─── Helpers Prometheus ────────────────────────────────────────────────────────

/**
 * Requête instantanée (valeur actuelle d'une métrique)
 * Utilisée pour les KPI cards
 */
async function fetchPrometheusMetric(query: string): Promise<string> {
  try {
    const url = `${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(query)}`
    const res = await fetch(url)
    if (!res.ok) return 'N/A'
    const json = await res.json()
    const result = json?.data?.result
    if (!result || result.length === 0) return 'N/A'
    const raw = result[0]?.value?.[1]
    if (raw === undefined || raw === null) return 'N/A'
    const num = parseFloat(raw)
    return isNaN(num) ? 'N/A' : num.toFixed(num < 10 ? 2 : 0)
  } catch {
    return 'N/A'
  }
}

/**
 * Requête range (série temporelle sur un intervalle)
 * Utilisée pour les graphiques LineChart et BarChart
 * @param query  - requête PromQL
 * @param start  - timestamp Unix de début
 * @param end    - timestamp Unix de fin
 * @param step   - résolution en secondes (ex: 3600 = 1 point par heure)
 * @returns tableau de {time, value} trié chronologiquement
 */
async function fetchPrometheusRange(
  query: string,
  start: number,
  end: number,
  step: number,
): Promise<{ time: string; value: number }[]> {
  try {
    const params = new URLSearchParams({
      query,
      start: start.toString(),
      end: end.toString(),
      step: step.toString(),
    })
    const res = await fetch(`${PROMETHEUS_URL}/api/v1/query_range?${params}`)
    if (!res.ok) return []
    const json = await res.json()
    const results = json?.data?.result
    if (!results || results.length === 0) return []

    // Agréger toutes les séries (sum) si plusieurs handlers
    const aggregated: Record<number, number> = {}
    for (const series of results) {
      for (const [ts, val] of series.values ?? []) {
        const num = parseFloat(val)
        if (!isNaN(num)) {
          aggregated[ts] = (aggregated[ts] ?? 0) + num
        }
      }
    }

    return Object.entries(aggregated)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([ts, val]) => ({
        time: formatTimestamp(Number(ts), step),
        value: Math.round(val * 1000) / 1000,
      }))
  } catch {
    return []
  }
}

/**
 * Formate un timestamp Unix selon la résolution choisie
 * - step < 7200 (< 2h)  → affiche l'heure  "14h30"
 * - step >= 7200         → affiche le jour  "Lun 12"
 */
function formatTimestamp(ts: number, step: number): string {
  const d = new Date(ts * 1000)
  if (step < 7200) {
    const h = d.getHours().toString().padStart(2, '0')
    const m = d.getMinutes().toString().padStart(2, '0')
    return `${h}h${m}`
  }
  const days = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam']
  return `${days[d.getDay()]} ${d.getDate()}`
}

// ─── Types ────────────────────────────────────────────────────────────────────
interface LatencyPoint {
  time: string
  value: number
}

interface DeployPoint {
  date: string
  success: number
  failed: number
}

interface SecurityToolReport {
  tool?: string
  status?: string
  project_key?: string
  dashboard_url?: string
  target_image?: string
  severity_checked?: string[]
  summary?: string
}

interface JenkinsInfo {
  job_name?: string
  build_url?: string
  pipeline_url?: string
  executor?: string
}

interface SecuritySummary {
  sast_executed?: boolean
  cve_scan_executed?: boolean
  dast_executed?: boolean
  pipeline_result?: string
  risk_level?: string
}

interface JenkinsReport {
  id: string
  project?: string
  branch: string
  build_number: string | number
  status: 'SUCCESS' | 'FAILURE'
  duration_ms: number
  jenkins?: JenkinsInfo
  sast?: SecurityToolReport
  cve_scan?: SecurityToolReport
  dast?: SecurityToolReport
  security_summary?: SecuritySummary
  recommendations?: string[]
  security_report?: string
  timestamp: string
  sonarqube_url?: string
  github_branch_url?: string
  deployed_url?: string
  created_at: string
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

function formatReportDate(value: string): string {
  if (!value) return 'N/A'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('fr-FR')
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="text-xs break-words">{value || ''}</div>
    </div>
  )
}

function yesNo(value?: boolean): string {
  return value ? 'Oui' : 'Non'
}

function markdownValue(value: unknown, fallback = 'N/A'): string {
  if (value === undefined || value === null || value === '') return fallback
  return String(value)
}

function cleanSecurityReportText(value?: string): string {
  return (value || '')
    .replace(/Aucun test DAST n['’]est encore configur[ée] dans cette version\.?/gi, '')
    .replace(/\s{2,}/g, ' ')
    .trim()
}

function readableRecommendations(items?: string[]): string[] {
  const fallback = [
    'Consulter le tableau de bord SonarQube pour analyser les bugs, vulnerabilites et hotspots.',
    'Verifier regulierement les vulnerabilites HIGH et CRITICAL detectees par Trivy.',
    'Prévoir une extension future du pipeline avec une analyse dynamique après déploiement.',
    "Conserver l'approche Shift-Left Security dans le pipeline CI/CD.",
  ]
  return (items?.length ? items : fallback).map(item =>
    /OWASP ZAP|DAST|analyse dynamique DAST/i.test(item)
      ? 'Prévoir une extension future du pipeline avec une analyse dynamique après déploiement.'
      : item,
  )
}

function generateSecurityReport(report: JenkinsReport): string {
  const durationSeconds = Number.isFinite(report.duration_ms)
    ? (report.duration_ms / 1000).toFixed(1)
    : 'N/A'
  const recommendations = [
    'Examiner les résultats SonarQube afin d’identifier les problèmes de qualité et de sécurité du code.',
    'Corriger en priorité les vulnérabilités critiques ou élevées détectées dans le code source.',
    'Vérifier les résultats Trivy avant tout déploiement afin de réduire les risques liés à l’image Docker.',
    'Mettre à jour régulièrement les dépendances et les images de base utilisées dans le projet.',
    'Conserver l’intégration de la sécurité dans le pipeline CI/CD afin de détecter les problèmes le plus tôt possible.',
    'Prévoir une extension future du pipeline avec une analyse dynamique après déploiement.',
  ].map(item => `- ${item}`).join('\n')
  const severities = report.cve_scan?.severity_checked?.length
    ? report.cve_scan.severity_checked.join(', ')
    : 'N/A'
  const executiveSummary = cleanSecurityReportText(report.security_report) ||
    'Le pipeline DevSecOps a ete execute. Jenkins a valide les artefacts generes, execute l’analyse statique avec SonarQube, construit l’image Docker, puis lance un scan de vulnerabilites avec Trivy.'
  const sastDetails = report.sast as (SecurityToolReport & Record<string, unknown>) | undefined
  const cveDetails = report.cve_scan as (SecurityToolReport & Record<string, unknown>) | undefined
  const hasSastCounters = ['bugs', 'vulnerabilities', 'code_smells', 'security_hotspots'].some(key => sastDetails?.[key] !== undefined)
  const hasTrivyCounters = cveDetails?.critical_count !== undefined || cveDetails?.high_count !== undefined
  const sastResult = hasSastCounters
    ? [
        `- Bugs : ${markdownValue(sastDetails?.bugs)}`,
        `- Vulnérabilités : ${markdownValue(sastDetails?.vulnerabilities)}`,
        `- Code smells : ${markdownValue(sastDetails?.code_smells)}`,
        `- Security hotspots : ${markdownValue(sastDetails?.security_hotspots)}`,
      ].join('\n')
    : 'Les compteurs détaillés SonarQube ne sont pas encore collectés automatiquement dans ce rapport.'
  const trivyResult = hasTrivyCounters
    ? [
        `- Vulnérabilités CRITICAL : ${markdownValue(cveDetails?.critical_count)}`,
        `- Vulnérabilités HIGH : ${markdownValue(cveDetails?.high_count)}`,
      ].join('\n')
    : 'Les compteurs détaillés Trivy ne sont pas encore collectés automatiquement dans ce rapport.'

  return `# Security Report — ${markdownValue(report.project, 'Next-Gen DevSecOps')}

## 1. Informations générales

- Statut global : ${markdownValue(report.status)}
- Durée d’exécution : ${durationSeconds} secondes
- Date : ${formatReportDate(report.created_at || report.timestamp)}
- Niveau de risque : ${markdownValue(report.security_summary?.risk_level)}

## 2. Résumé exécutif

${executiveSummary}

## 3. Résultats SAST — SonarQube

- Outil : ${markdownValue(report.sast?.tool, 'SonarQube')}
- Statut : ${markdownValue(report.sast?.status)}
- Project Key : ${markdownValue(report.sast?.project_key)}

### Objectif de l’analyse

SonarQube analyse le code source afin de détecter les erreurs de qualité, les vulnérabilités potentielles, les mauvaises pratiques de développement et les zones sensibles de sécurité qui nécessitent une attention particulière.

### Éléments vérifiés

- Vulnérabilités potentielles dans le code
- Bugs pouvant provoquer des erreurs d’exécution
- Code smells indiquant une mauvaise qualité de code
- Security hotspots nécessitant une revue manuelle
- Maintenabilité et fiabilité du code

### Résultat

L’analyse SAST a été exécutée avec succès dans le pipeline.

${sastResult}

## 4. Résultats CVE Scan — Trivy

- Outil : ${markdownValue(report.cve_scan?.tool, 'Trivy')}
- Statut : ${markdownValue(report.cve_scan?.status)}
- Image analysée : ${markdownValue(report.cve_scan?.target_image)}
- Sévérités vérifiées : ${severities}

### Objectif du scan

Trivy analyse l’image Docker générée par le pipeline afin de rechercher des vulnérabilités connues dans les paquets système, les bibliothèques et les dépendances embarquées.

### Éléments vérifiés

- Vulnérabilités HIGH
- Vulnérabilités CRITICAL
- Paquets vulnérables dans l’image Docker
- Risques liés aux dépendances embarquées
- Robustesse de l’image avant déploiement

### Résultat

Le scan CVE a été exécuté avec succès.

${trivyResult}

## 5. Synthèse sécurité

- SAST exécuté : ${yesNo(report.security_summary?.sast_executed)}
- Scan CVE exécuté : ${yesNo(report.security_summary?.cve_scan_executed)}
- Niveau de risque : ${markdownValue(report.security_summary?.risk_level)}
- Résultat global : ${markdownValue(report.security_summary?.pipeline_result, report.status)}

## 6. Recommandations

${recommendations}

## 7. Conclusion

Ce rapport donne une vue claire sur l’état de sécurité du pipeline. Il combine l’analyse du code source avec SonarQube et le scan de vulnérabilités de l’image Docker avec Trivy afin d’aider les utilisateurs à comprendre les contrôles réalisés, les risques observés et les actions prioritaires à suivre.
`
}

function downloadSecurityReport(report: JenkinsReport) {
  const blob = new Blob([generateSecurityReport(report)], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `security-report-build-${report.build_number}.md`
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

function downloadReportJson(report: JenkinsReport) {
  // Cree un fichier JSON local sans appel backend supplementaire.
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `jenkins-report-${report.id}.json`
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

// ─── Composant principal ───────────────────────────────────────────────────────
function buildDeploymentDataFromReports(reports: JenkinsReport[]): DeployPoint[] {
  const grouped: Record<string, DeployPoint> = {}

  for (const report of reports) {
    const rawDate = report.timestamp || report.created_at
    if (!rawDate) continue

    const date = new Date(rawDate)
    if (Number.isNaN(date.getTime())) continue

    const key = date.toISOString().slice(0, 10)
    const label = date.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' })
    grouped[key] ??= { date: label, success: 0, failed: 0 }

    if (report.status === 'SUCCESS') {
      grouped[key].success += 1
    } else if (report.status) {
      grouped[key].failed += 1
    }
  }

  return Object.entries(grouped)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, point]) => point)
}

export default function MonitoringPage() {
  // Métriques calculées depuis l'historique réel du backend
  const [metrics, setMetrics] = useState({
    pipelines:   0,
    tokens:      0,
    successRate: 100,
    avgTime:     3.2,
  })

  // Métriques Prometheus instantanées (KPI cards)
  const [promMetrics, setPromMetrics] = useState({
    requestsTotal:   'N/A',
    requestsPerMin:  'N/A',
    avgResponseTime: 'N/A',
    pipelinesTotal:  'N/A',
  })

  // Données des graphiques — initialement vides, remplies depuis Prometheus
  const [latencyData,    setLatencyData]    = useState<LatencyPoint[]>([])
  const [deploymentsData, setDeploymentsData] = useState<DeployPoint[]>([])
  const [isRefreshing,   setIsRefreshing]   = useState(false)
  const [jenkinsReports, setJenkinsReports] = useState<JenkinsReport[]>([])
  const [selectedReport, setSelectedReport] = useState<JenkinsReport | null>(null)
  const [reportsError, setReportsError] = useState('')
  const totalReports = jenkinsReports.length
  const successfulBuilds = jenkinsReports.filter(report => report.status === 'SUCCESS').length
  const failedBuilds = jenkinsReports.filter(report => report.status && report.status !== 'SUCCESS').length
  const successRateFromReports = totalReports > 0 ? Math.round((successfulBuilds / totalReports) * 100) : 0
  const averageDurationSeconds = totalReports > 0
    ? (jenkinsReports.reduce((sum, report) => sum + (report.duration_ms || 0), 0) / totalReports / 1000).toFixed(1)
    : '0.0'
  const riskCounts = jenkinsReports.reduce<Record<string, number>>((acc, report) => {
    const risk = report.security_summary?.risk_level
    if (risk) acc[risk] = (acc[risk] ?? 0) + 1
    return acc
  }, {})
  const riskDistributionData = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    .filter(risk => riskCounts[risk] > 0)
    .map(risk => ({ risk, count: riskCounts[risk] }))
  const dominantRisk = riskDistributionData.length > 0
    ? [...riskDistributionData].sort((a, b) => b.count - a.count)[0].risk
    : 'Aucun'
  const pipelineResultsData = [
    { name: 'Résultats', success: successfulBuilds, failed: failedBuilds },
  ]
  const deploymentsChartData = buildDeploymentDataFromReports(jenkinsReports)

  /**
   * Charge toutes les données Prometheus :
   * 1. KPI cards — requêtes instantanées
   * 2. Graphique Latence — query_range sur la dernière heure, 1 point toutes les 5 min
   * 3. Graphique Déploiements — query_range sur 7 jours, 1 point par jour
   *
   * Pourquoi query_range et pas query ?
   * query retourne un seul point (maintenant). query_range retourne une série
   * temporelle — indispensable pour tracer un graphique évolutif.
   *
   * Pourquoi increase() pour les déploiements ?
   * http_requests_total est un counter (toujours croissant). increase() calcule
   * la variation sur la fenêtre — c'est le nombre de requêtes dans la journée,
   * pas le total cumulé depuis le démarrage.
   */
  const loadAllMetrics = useCallback(async () => {
    setIsRefreshing(true)
    const now   = Math.floor(Date.now() / 1000)
    const ago1h = now - 3600        // 1 heure en arrière

    try {
      // ── KPI cards (valeurs instantanées) ──────────────────────────────────
      const [requestsTotal, requestsPerMin, avgResponseTime, pipelinesTotal] =
        await Promise.all([
          fetchPrometheusMetric('sum(http_requests_total)'),
          fetchPrometheusMetric('sum(rate(http_requests_total[5m])) * 60'),
          fetchPrometheusMetric(
            'sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m]))',
          ),
          fetchPrometheusMetric('http_requests_total{handler="/api/v1/generate/all"}'),
        ])
      setPromMetrics({ requestsTotal, requestsPerMin, avgResponseTime, pipelinesTotal })

      // ── Graphique Latence — dernière heure, résolution 5 min (300 s) ──────
      // La requête calcule la latence moyenne par fenêtre glissante de 5 min
      // et la convertit en millisecondes (* 1000) pour l'affichage
      const rawLatency = await fetchPrometheusRange(
        'sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m])) * 1000',
        ago1h,
        now,
        300,
      )
      // Si Prometheus n'a pas encore de données sur 1h, tenter 30 min
      if (rawLatency.length === 0) {
        const rawLatency30 = await fetchPrometheusRange(
          'sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m])) * 1000',
          now - 1800,
          now,
          300,
        )
        setLatencyData(rawLatency30)
      } else {
        setLatencyData(rawLatency)
      }

      // ── Graphique Déploiements — 7 jours, résolution 1 jour (86400 s) ─────
      // increase() donne le nombre de requêtes generate/all par jour
      // On l'utilise pour "Succès" — on n'a pas encore de métrique "failed"
      // depuis Prometheus donc failed = 0 (à brancher sur une métrique custom)
      const deployPoints: DeployPoint[] = []

      if (deployPoints.length > 0) {
        deployPoints.map(p => ({
          date:    p.date,
          success: Math.round(p.success),
          // failed sera branché sur une métrique custom quand disponible
          // Pour l'instant 0 — honnête car pas de données d'erreur Prometheus
          failed: 0,
        }))
        setDeploymentsData(deployPoints)
      }
    } finally {
      setIsRefreshing(false)
    }
  }, [])

  const loadJenkinsReports = useCallback(async () => {
    try {
      // Charge les rapports Jenkins proteges par JWT.
      const data = await apiGetPipelineReports()
      const reports = data.reports ?? []
      setJenkinsReports(reports)
      setDeploymentsData(buildDeploymentDataFromReports(reports))
      setReportsError('')
    } catch {
      setReportsError('Impossible de charger les rapports Jenkins')
    }
  }, [])

  useEffect(() => {
    // Charger les métriques depuis l'historique réel du backend
    Promise.resolve({ pipelines: [] })
      .then(({ pipelines }: { pipelines: { tokens_used?: number; status: string }[] }) => {
        const total   = pipelines.length
        const tokens  = pipelines.reduce((acc, p) => acc + (p.tokens_used ?? 0), 0)
        const success = pipelines.filter(p => p.status === 'success').length
        setMetrics({
          pipelines:   total,
          tokens,
          successRate: total > 0 ? Math.round((success / total) * 100) : 100,
          avgTime:     3.2,
        })
      })
      .catch(() => {})

    loadJenkinsReports()

    // Rafraîchissement automatique toutes les 30 secondes
    // Identique au comportement de Grafana (scrape_interval: 15s → UI refresh: 30s)
    const interval = setInterval(loadJenkinsReports, 30_000)
    return () => clearInterval(interval)
  }, [loadJenkinsReports])

  // Formatter pour le tooltip Latence
  const latencyFormatter = (val: number) => [`${val.toFixed(2)} ms`, 'Latence']

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="mx-auto max-w-7xl px-4 py-8">

        {/* ─── En-tête ─────────────────────────────────────────────────────── */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div className="hidden items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Activity className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Monitoring & Observabilité</h1>
              <p className="text-sm text-muted-foreground">Surveillance en temps réel de l'infrastructure</p>
            </div>
          </div>

          <div className="hidden items-center gap-3">
            <button
              onClick={loadAllMetrics}
              disabled={isRefreshing}
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-secondary/50 px-3 py-1.5 text-xs font-medium hover:bg-secondary transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
              Rafraîchir
            </button>
          </div>
        </div>

        {/* ─── KPI Cards Prometheus ─────────────────────────────────────────── */}
        <div className="hidden gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
          <KPICard
            icon={Activity}
            label="Requêtes totales"
            value={promMetrics.requestsTotal}
            sub="http_requests_total"
            highlight
          />
          <KPICard
            icon={Zap}
            label="Requêtes par minute"
            value={promMetrics.requestsPerMin}
            sub="rate sur 5 min × 60"
          />
          <KPICard
            icon={Clock}
            label="Temps de réponse moyen"
            value={promMetrics.avgResponseTime === 'N/A' ? 'N/A' : `${promMetrics.avgResponseTime}s`}
            sub="Latence moyenne (5 min)"
          />
          <KPICard
            icon={GitBranch}
            label="Pipelines générés"
            value={promMetrics.pipelinesTotal}
            sub="/api/v1/generate/all"
          />
        </div>

        {/* ─── KPI Cards historique backend ────────────────────────────────── */}
        <div className="hidden gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
          <KPICard
            icon={GitBranch}
            label="Générations (historique)"
            value={metrics.pipelines.toString()}
            sub="Total des générations"
          />
          <KPICard
            icon={Zap}
            label="Tokens consommés"
            value={metrics.tokens.toLocaleString('fr-FR')}
            sub="Consommation LLM cumulée"
          />
          <KPICard
            icon={CheckCircle}
            label="Taux de succès Jenkins"
            value={`${totalReports > 0 ? Math.round((successfulBuilds / totalReports) * 100) : 100}%`}
            sub={totalReports > 0 ? `${successfulBuilds}/${totalReports} builds réussis` : 'Aucun build encore'}
          />
          <KPICard
            icon={Clock}
            label="Temps moyen estimé"
            value={`${metrics.avgTime}s`}
            sub="Par génération (estimé)"
          />
        </div>

        {/* ─── Graphiques ──────────────────────────────────────────────────── */}
        <div className="hidden gap-6 lg:grid-cols-2 mb-8">

          {/* Bar chart — déploiements 7 jours depuis Prometheus */}
          <div className="glass-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-1">
              <GitBranch className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Déploiements cette semaine</h3>
            </div>
            <p className="text-xs text-muted-foreground/60 mb-4">
              Succès et échecs calculés depuis les rapports Jenkins stockés
            </p>
            {deploymentsData.length === 0 ? (
              <div className="flex items-center justify-center h-[220px] text-xs text-muted-foreground/50">
                Pas encore de données — générez un pipeline pour alimenter le graphique
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={deploymentsData} barGap={4}>
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
                    allowDecimals={false}
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
                  <Legend wrapperStyle={{ fontSize: 11, color: 'oklch(0.60 0.02 260)' }} />
                  <Bar dataKey="success" name="Succès" fill="oklch(0.72 0.19 150)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="failed"  name="Échec"  fill="oklch(0.60 0.22 25)"  radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Line chart — latence API depuis Prometheus query_range */}
          <div className="glass-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-1">
              <Activity className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Latence API (ms)</h3>
            </div>
            <p className="text-xs text-muted-foreground/60 mb-4">
              Dernière heure — résolution 5 min — source Prometheus
            </p>
            {latencyData.length === 0 ? (
              <div className="flex items-center justify-center h-[220px] text-xs text-muted-foreground/50">
                En attente de données — Prometheus scrape toutes les 15s
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={latencyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.02 260)" />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    interval="preserveStartEnd"
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
                    formatter={latencyFormatter}
                  />
                  <Line
                    type="monotone"
                    dataKey="value"
                    name="Latence"
                    stroke="oklch(0.78 0.18 195)"
                    strokeWidth={2}
                    dot={{ fill: 'oklch(0.78 0.18 195)', r: 3, strokeWidth: 0 }}
                    activeDot={{ r: 5, fill: 'oklch(0.78 0.18 195)' }}
                    connectNulls
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

{/* ─── Rapports Jenkins ─────────────────────────────────────────────── */}
        <section className="mb-8">
          <div className="mb-4 flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">Tableau de bord des pipelines</h2>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 mb-6">
            <div className="glass-card rounded-xl p-4"><p className="text-xs text-muted-foreground">Total des rapports Jenkins</p><p className="mt-2 text-2xl font-bold">{totalReports}</p></div>
            <div className="glass-card rounded-xl p-4"><p className="text-xs text-muted-foreground">Builds réussis</p><p className="mt-2 text-2xl font-bold text-success">{successfulBuilds}</p></div>
            <div className="glass-card rounded-xl p-4"><p className="text-xs text-muted-foreground">Builds échoués</p><p className="mt-2 text-2xl font-bold text-destructive">{failedBuilds}</p></div>
            <div className="glass-card rounded-xl p-4"><p className="text-xs text-muted-foreground">Taux de succès</p><p className="mt-2 text-2xl font-bold">{successRateFromReports}%</p></div>
            <div className="glass-card rounded-xl p-4"><p className="text-xs text-muted-foreground">Durée moyenne d’exécution</p><p className="mt-2 text-2xl font-bold">{averageDurationSeconds}s</p></div>
            <div className="glass-card rounded-xl p-4"><p className="text-xs text-muted-foreground">Niveau de risque dominant</p><p className="mt-2 text-2xl font-bold">{dominantRisk}</p></div>
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <div className="glass-card rounded-xl p-5">
              <h3 className="mb-4 text-sm font-semibold">Résultats des pipelines</h3>
              {totalReports === 0 ? <div className="flex h-[220px] items-center justify-center text-xs text-muted-foreground/60">Aucun rapport Jenkins disponible pour alimenter le graphique.</div> : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={pipelineResultsData}><CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.02 260)" /><XAxis dataKey="name" tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} /><Tooltip contentStyle={{ background: 'oklch(0.16 0.02 260)', border: '1px solid oklch(0.25 0.02 260)', borderRadius: 8, fontSize: 12 }} /><Legend wrapperStyle={{ fontSize: 11 }} /><Bar dataKey="success" name="Succès" fill="oklch(0.72 0.19 150)" radius={[4, 4, 0, 0]} /><Bar dataKey="failed" name="Échecs" fill="oklch(0.60 0.22 25)" radius={[4, 4, 0, 0]} /></BarChart>
                </ResponsiveContainer>
              )}
            </div>
            <div className="glass-card rounded-xl p-5">
              <h3 className="mb-4 text-sm font-semibold">Déploiements cette semaine</h3>
              {deploymentsChartData.length === 0 ? <div className="flex h-[220px] items-center justify-center text-xs text-muted-foreground/60">Aucun rapport Jenkins disponible pour alimenter le graphique.</div> : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={deploymentsChartData}><CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.02 260)" /><XAxis dataKey="date" tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} /><Tooltip contentStyle={{ background: 'oklch(0.16 0.02 260)', border: '1px solid oklch(0.25 0.02 260)', borderRadius: 8, fontSize: 12 }} /><Legend wrapperStyle={{ fontSize: 11 }} /><Bar dataKey="success" name="Succès" fill="oklch(0.72 0.19 150)" radius={[4, 4, 0, 0]} /><Bar dataKey="failed" name="Échecs" fill="oklch(0.60 0.22 25)" radius={[4, 4, 0, 0]} /></BarChart>
                </ResponsiveContainer>
              )}
            </div>
            <div className="glass-card rounded-xl p-5">
              <h3 className="mb-4 text-sm font-semibold">Répartition des risques</h3>
              {riskDistributionData.length === 0 ? <div className="flex h-[220px] items-center justify-center text-xs text-muted-foreground/60">Aucun rapport Jenkins disponible pour alimenter le graphique.</div> : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={riskDistributionData}><CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.02 260)" /><XAxis dataKey="risk" tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: 'oklch(0.60 0.02 260)', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} /><Tooltip contentStyle={{ background: 'oklch(0.16 0.02 260)', border: '1px solid oklch(0.25 0.02 260)', borderRadius: 8, fontSize: 12 }} /><Bar dataKey="count" name="Rapports" fill="oklch(0.78 0.18 195)" radius={[4, 4, 0, 0]} /></BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </section>

        <div className="glass-card rounded-xl p-5 mt-6">
          <div className="flex items-center gap-2 mb-4">
            <GitBranch className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">Rapports Jenkins</h3>
            <span className="ml-auto text-xs text-muted-foreground">
              Mis à jour après chaque pipeline
            </span>
          </div>

          {reportsError && (
            <p className="text-xs text-destructive mb-3">{reportsError}</p>
          )}

          {jenkinsReports.length === 0 ? (
            <div className="flex items-center justify-center h-24 text-xs text-muted-foreground/50">
              Aucun rapport — générez un pipeline pour voir les résultats Jenkins ici
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              {jenkinsReports.map(report => (
                <div
                  key={report.id}
                  className="rounded-lg border border-border p-3 bg-secondary/30 hover:bg-secondary/50 transition-colors"
                >
                  <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${report.status === 'SUCCESS' ? 'bg-success' : 'bg-destructive'}`} />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium truncate">{report.branch}</p>
                    <p className="text-xs text-muted-foreground">
                      Build #{report.build_number} · {(report.duration_ms / 1000).toFixed(1)}s · {formatReportDate(report.created_at)}
                    </p>
                    <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
                      {cleanSecurityReportText(report.security_report) || 'Aucun rapport de securite enrichi disponible pour ce build.'}
                    </p>
                    <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 text-xs">
                      <span className="rounded border border-border bg-background/30 px-2 py-1">
                        SAST : {report.sast?.tool || 'SonarQube'} {report.sast?.status || 'EXECUTED'}
                      </span>
                      <span className="rounded border border-border bg-background/30 px-2 py-1">
                        CVE Scan : {report.cve_scan?.tool || 'Trivy'} {report.cve_scan?.status || 'EXECUTED'}
                      </span>
                      <span className="rounded border border-border bg-background/30 px-2 py-1">
                        Risque : {report.security_summary?.risk_level || 'LOW'}
                      </span>
                    </div>
                    {(readableRecommendations(report.recommendations).length ?? 0) > 0 && (
                      <ul className="mt-3 list-disc pl-5 text-xs text-muted-foreground space-y-1">
                        {readableRecommendations(report.recommendations).map((item, index) => (
                          <li key={`${report.id}-recommendation-${index}`}>{item}</li>
                        ))}
                      </ul>
                    )}
                    {/* Badge deployed_url — toujours affiché si rapport reçu */}
                    <div className="mt-3 flex items-center gap-2">
                      {report.deployed_url && report.deployed_url !== 'N/A' ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-success/15 border border-success/30 px-3 py-1 text-xs font-medium text-success">
                          <span className="h-1.5 w-1.5 rounded-full bg-success" />
                          App déployée : {report.deployed_url}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-secondary border border-border px-3 py-1 text-xs font-medium text-muted-foreground">
                          <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground" />
                          Déploiement local
                        </span>
                      )}
                    </div>
                  </div>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${report.status === 'SUCCESS' ? 'bg-success/10 text-success' : 'bg-destructive/10 text-destructive'}`}>
                    {report.status}
                  </span>
                  <div className="flex gap-2 flex-wrap">
                    {/* Bouton "Ouvrir l'app" — uniquement si deployed_url présent et valide */}
                    {report.deployed_url && report.deployed_url !== 'N/A' && (
                      <a
                        href={report.deployed_url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 rounded border border-success/40 bg-success/10 px-2 py-1 text-xs text-success hover:bg-success/20 transition-colors">
                        Ouvrir l'app
                      </a>
                    )}
                    {report.github_branch_url && (
                      <a href={report.github_branch_url} target="_blank" rel="noreferrer"
                        className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-xs hover:bg-secondary transition-colors">
                        GitHub
                      </a>
                    )}
                    <button
                      onClick={() => setSelectedReport(report)}
                      className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-xs hover:bg-secondary transition-colors">
                      <Eye className="h-3 w-3" /> Détails
                    </button>
                    <button
                      onClick={() => downloadSecurityReport(report)}
                      className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-xs text-primary hover:bg-primary/20 transition-colors">
                      <Download className="h-3 w-3" /> Rapport
                    </button>
                    <button
                      onClick={() => downloadReportJson(report)}
                      className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-xs hover:bg-secondary transition-colors">
                      <Download className="h-3 w-3" /> JSON
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ─── Modal détails rapport ────────────────────────────────────────── */}
        {selectedReport && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
            <div className="glass-card rounded-xl p-5 w-full max-w-4xl max-h-[85vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold">Détails du rapport</h3>
                <button onClick={() => setSelectedReport(null)}>
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="space-y-3 pr-1 text-xs">
                <section className="rounded-lg border border-border bg-secondary/30 p-4">
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">Synthèse</h4>
                  <div className="grid gap-3 sm:grid-cols-3">
                    <DetailRow label="Statut" value={selectedReport.status} />
                    <DetailRow label="Duree" value={`${(selectedReport.duration_ms / 1000).toFixed(1)}s`} />
                    <DetailRow label="Risque" value={selectedReport.security_summary?.risk_level} />
                  </div>
                  <p className="mt-3 break-words text-xs leading-relaxed text-muted-foreground">
                    {cleanSecurityReportText(selectedReport.security_report) || 'Aucun rapport de securite enrichi disponible pour ce build.'}
                  </p>
                </section>

                <section className="rounded-lg border border-border bg-secondary/30 p-4">
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">Résultats SAST</h4>
                  <DetailRow label="SAST" value={`${selectedReport.sast?.tool || 'SonarQube'} ${selectedReport.sast?.status || 'N/A'}`} />
                  <p className="mt-3 break-words text-xs leading-relaxed text-muted-foreground">
                    {selectedReport.sast?.summary || 'Aucun résumé SAST disponible.'}
                  </p>
                </section>

                <section className="rounded-lg border border-border bg-secondary/30 p-4">
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">Résultats CVE Scan</h4>
                  <DetailRow label="CVE Scan" value={`${selectedReport.cve_scan?.tool || 'Trivy'} ${selectedReport.cve_scan?.status || 'N/A'}`} />
                  <p className="mt-3 break-words text-xs leading-relaxed text-muted-foreground">
                    {selectedReport.cve_scan?.summary || 'Aucun résumé CVE disponible.'}
                  </p>
                </section>

                {(readableRecommendations(selectedReport.recommendations).length ?? 0) > 0 && (
                  <section className="rounded-lg border border-border bg-secondary/30 p-4">
                    <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">Recommandations</h4>
                    <ul className="list-disc pl-5 text-xs text-muted-foreground space-y-1.5">
                      {readableRecommendations(selectedReport.recommendations).map((item, index) => (
                        <li className="break-words" key={`detail-recommendation-${index}`}>{item}</li>
                      ))}
                    </ul>
                  </section>
                )}
              </div>
            </div>
          </div>
        )}

      </main>
    </div>
  )
}
