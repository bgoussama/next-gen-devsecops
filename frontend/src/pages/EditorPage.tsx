// Éditeur de pipeline — affichage par onglets, copier/télécharger
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileCode, Copy, Download, Check, Bot, ShieldCheck } from 'lucide-react'
import { Navbar } from '../components/Navbar'

// ─── Types ────────────────────────────────────────────────────────────────────
interface GenerationData {
  id: string
  prompt: string
  // Nouveau format — 4 artefacts séparés (apiGenerateAll)
  jenkinsfile?: string
  terraform?: string
  dockerfile?: string
  k8s_manifest?: string
  github_branch_url?: string
  // Ancien format — compatibilité descendante (apiGenerate)
  pipeline_content?: string
  tokens_used: number
  threat_score?: number
  threat_risk_level?: string
  threat_techniques?: ThreatTechnique[]
  threat_recommendations?: string[]
  threat_summary?: string
  created_at: string
}

interface ThreatTechnique {
  id: string
  name: string
  status: 'PROTECTED' | 'AT_RISK' | 'UNKNOWN'
  description: string
  evidence: string
}

type TabKey = 'jenkinsfile' | 'terraform' | 'dockerfile' | 'kubernetes' | 'threat'

const TABS: { key: TabKey; label: string; filename: string }[] = [
  { key: 'jenkinsfile', label: 'Jenkinsfile',  filename: 'Jenkinsfile' },
  { key: 'terraform',   label: 'Terraform',    filename: 'main.tf' },
  { key: 'dockerfile',  label: 'Dockerfile',   filename: 'Dockerfile' },
  { key: 'kubernetes',  label: 'Kubernetes',   filename: 'k8s-manifest.yaml' },
  { key: 'threat',      label: 'Threat Analysis', filename: 'threat-analysis.txt' },
]

// Contenu de placeholder pour les onglets non générés par le backend actuel
const PLACEHOLDER: Record<string, string> = {
  terraform: `# Terraform — généré automatiquement en Phase 9
# (actuellement le backend retourne uniquement le Jenkinsfile)

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}`,
  dockerfile: `# Dockerfile multi-stage — à venir en Phase 9
# (actuellement le backend retourne uniquement le Jenkinsfile)

FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=builder /app/dist ./dist
EXPOSE 3000
CMD ["node", "dist/index.js"]`,
  kubernetes: `# Kubernetes Manifest — à venir en Phase 9
# (actuellement le backend retourne uniquement le Jenkinsfile)

apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deployment
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nextgen-app
  template:
    metadata:
      labels:
        app: nextgen-app
    spec:
      containers:
        - name: app
          image: registry/app:latest
          ports:
            - containerPort: 3000`,
}

// ─── Code avec numéros de lignes ──────────────────────────────────────────────
function CodeView({ code }: { code: string }) {
  const lines = code.split('\n')
  return (
    <div className="flex font-mono text-xs overflow-x-auto terminal-scrollbar">
      {/* Numéros de lignes */}
      <div className="select-none pr-4 text-right text-muted-foreground/40 min-w-[3rem] shrink-0">
        {lines.map((_, i) => (
          <div key={i} className="leading-6">{i + 1}</div>
        ))}
      </div>
      {/* Code */}
      <pre className="flex-1 leading-6 text-foreground/90 whitespace-pre">{code}</pre>
    </div>
  )
}

function scoreBadgeClass(score: number) {
  if (score > 80) return 'border-success/30 bg-success/10 text-success'
  if (score >= 60) return 'border-warning/30 bg-warning/10 text-warning'
  return 'border-destructive/30 bg-destructive/10 text-destructive'
}

function scoreBarClass(score: number) {
  if (score > 80) return 'bg-success'
  if (score >= 60) return 'bg-warning'
  return 'bg-destructive'
}

function statusClass(status: ThreatTechnique['status']) {
  if (status === 'PROTECTED') return 'text-success'
  if (status === 'AT_RISK') return 'text-destructive'
  return 'text-warning'
}

function fallbackRecommendations(techniques: ThreatTechnique[]) {
  const recommendations = techniques
    .filter(technique => technique.status === 'AT_RISK')
    .map(technique => {
      if (technique.id === 'T1552') return 'Externaliser les secrets avec Vault, AWS Secrets Manager, Jenkins credentials ou secrets Kubernetes.'
      if (technique.id === 'T1190') return 'Limiter les security groups aux CIDR necessaires et eviter 0.0.0.0/0 sur tous les ports.'
      if (technique.id === 'T1525') return 'Utiliser des tags immuables, signer les images et executer les conteneurs avec un utilisateur non-root.'
      if (technique.id === 'T1195') return 'Ajouter un stage Jenkins de scan avec Trivy, Snyk, OWASP Dependency-Check ou Grype.'
      return 'Remplacer les comptes IAM permanents ou administrateurs par des roles a moindre privilege.'
    })

  return recommendations.length > 0
    ? recommendations
    : ['Maintenir les scans de securite et revoir regulierement les controles MITRE ATT&CK.']
}

function buildThreatReport(data: GenerationData) {
  const techniques = data.threat_techniques || []
  const recommendations = data.threat_recommendations?.length
    ? data.threat_recommendations
    : fallbackRecommendations(techniques)

  return [
    'Rapport MITRE ATT&CK',
    `Score: ${data.threat_score || 0}/100`,
    `Niveau de risque: ${data.threat_risk_level || 'UNKNOWN'}`,
    data.threat_summary || '',
    '',
    'Techniques:',
    ...techniques.map(technique => `${technique.id} - ${technique.name}: ${technique.status} - ${technique.description}`),
    '',
    'Recommandations:',
    ...recommendations.map(item => `- ${item}`),
  ].join('\n')
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function ThreatAnalysisView({ data }: { data: GenerationData }) {
  const score = data.threat_score || 0
  const riskLevel = data.threat_risk_level || 'UNKNOWN'
  const techniques = data.threat_techniques || []
  const recommendations = data.threat_recommendations?.length
    ? data.threat_recommendations
    : fallbackRecommendations(techniques)

  const handleExportPdf = () => {
    const printWindow = window.open('', '_blank')
    if (!printWindow) return

    printWindow.document.write(`
      <html>
        <head><title>Rapport MITRE ATT&CK</title></head>
        <body style="font-family: Arial, sans-serif; padding: 24px;">
          <h1>Rapport MITRE ATT&CK</h1>
          <p><strong>Score:</strong> ${score}/100</p>
          <p><strong>Niveau de risque:</strong> ${escapeHtml(riskLevel)}</p>
          <h2>Techniques</h2>
          <ul>${techniques.map(t => `<li><strong>${escapeHtml(t.id)} - ${escapeHtml(t.name)}</strong>: ${escapeHtml(t.status)}<br/>${escapeHtml(t.description)}</li>`).join('')}</ul>
          <h2>Recommandations</h2>
          <ul>${recommendations.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
        </body>
      </html>
    `)
    printWindow.document.close()
    printWindow.print()
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-4 rounded-lg border border-border bg-secondary/20 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <div>
            <h2 className="text-sm font-semibold">Score de sécurité MITRE ATT&CK</h2>
            <p className="text-xs text-muted-foreground">{data.threat_summary || 'Analyse des 5 techniques principales.'}</p>
          </div>
        </div>
        <button
          onClick={handleExportPdf}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground hover:bg-secondary hover:text-foreground transition-colors"
        >
          <Download className="h-3.5 w-3.5" />
          Exporter rapport PDF
        </button>
      </div>

      <div className="rounded-lg border border-border p-4">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground">Score</span>
          <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${scoreBadgeClass(score)}`}>
            {score}/100 · {riskLevel}
          </span>
        </div>
        <div className="h-3 rounded-full bg-secondary">
          <div
            className={`h-3 rounded-full ${scoreBarClass(score)}`}
            style={{ width: `${score}%` }}
          />
        </div>
      </div>

      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-xs">
          <thead className="bg-secondary/50 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">ID</th>
              <th className="px-3 py-2 font-medium">Technique</th>
              <th className="px-3 py-2 font-medium">Statut</th>
              <th className="px-3 py-2 font-medium">Preuve</th>
            </tr>
          </thead>
          <tbody>
            {techniques.map(technique => (
              <tr key={technique.id} className="border-t border-border">
                <td className="px-3 py-2 font-mono">{technique.id}</td>
                <td className="px-3 py-2">
                  <div className="font-medium">{technique.name}</div>
                  <div className="text-muted-foreground">{technique.description}</div>
                </td>
                <td className={`px-3 py-2 font-semibold ${statusClass(technique.status)}`}>
                  {technique.status}
                </td>
                <td className="px-3 py-2 text-muted-foreground">{technique.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-lg border border-border p-4">
        <h3 className="mb-3 text-sm font-semibold">Recommandations</h3>
        <ul className="space-y-2 text-xs text-muted-foreground">
          {recommendations.map((item, index) => (
            <li key={`${item}-${index}`} className="rounded-md bg-secondary/30 px-3 py-2">{item}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}

// ─── Composant principal ───────────────────────────────────────────────────────
export default function EditorPage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<TabKey>('jenkinsfile')
  const [copied, setCopied] = useState(false)

  // Lecture de la dernière génération depuis localStorage
  const raw = localStorage.getItem('lastGeneration')
  const data: GenerationData | null = raw ? JSON.parse(raw) : null

  const unescape = (s: string) => s.replace(/\\n/g, '\n')

  // Construction de la map — champs nouveaux en priorité, fallback sur pipeline_content
  const codeMap: Record<TabKey, string> = {
    jenkinsfile: unescape(data?.jenkinsfile || data?.pipeline_content || ''),
    terraform:   unescape(data?.terraform   || PLACEHOLDER.terraform),
    dockerfile:  unescape(data?.dockerfile  || PLACEHOLDER.dockerfile),
    kubernetes:  unescape(data?.k8s_manifest || PLACEHOLDER.kubernetes),
    threat:      data ? buildThreatReport(data) : '',
  }

  const currentCode = codeMap[activeTab]
  const currentTab  = TABS.find(t => t.key === activeTab)!

  const handleCopy = async () => {
    await navigator.clipboard.writeText(currentCode)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    const blob = new Blob([currentCode], { type: 'text/plain' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = currentTab.filename
    a.click()
    URL.revokeObjectURL(url)
  }

  // Aucune génération disponible
  if (!data) {
    return (
      <div className="min-h-screen bg-background">
        <Navbar />
        <main className="mx-auto max-w-6xl px-4 py-16 text-center">
          <div className="glass-card rounded-2xl p-10 inline-block">
            <Bot className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h2 className="text-lg font-semibold mb-2">Aucune génération disponible</h2>
            <p className="text-sm text-muted-foreground mb-6">
              Générez d'abord un pipeline avec le Générateur IA.
            </p>
            <button
              onClick={() => navigate('/generator')}
              className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              Aller au Générateur
            </button>
          </div>
        </main>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="mx-auto max-w-6xl px-4 py-8">
        {/* En-tête */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <FileCode className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Éditeur & Aperçu</h1>
              <p className="text-sm text-muted-foreground">
                Généré le {new Date(data.created_at).toLocaleDateString('fr-FR')} • {data.tokens_used.toLocaleString('fr-FR')} tokens
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-secondary transition-colors"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? 'Copié !' : 'Copier'}
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              Télécharger
            </button>
          </div>
        </div>

        {/* Badges de sécurité */}
        <div className="flex flex-wrap gap-2 mb-5">
          <span className="inline-flex items-center gap-1.5 rounded-full bg-success/10 border border-success/20 px-3 py-1 text-xs font-medium text-success">
            <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse-glow" />
            Shift-Left Security
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/10 border border-primary/20 px-3 py-1 text-xs text-primary">
            SonarQube intégré
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-full bg-accent/10 border border-accent/20 px-3 py-1 text-xs text-accent">
            Bandit + Safety
          </span>
        </div>

        {/* Prompt d'origine */}
        <div className="glass-card rounded-xl p-3 mb-4 flex items-start gap-2">
          <Bot className="h-4 w-4 text-primary shrink-0 mt-0.5" />
          <p className="text-xs text-muted-foreground line-clamp-2">{data.prompt}</p>
        </div>

        {/* Onglets */}
        <div className="flex gap-1 mb-0 border-b border-border">
          {TABS.map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                activeTab === tab.key
                  ? 'bg-card border border-b-0 border-border text-foreground'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Bloc de code */}
        <div className="glass-card rounded-b-xl rounded-tr-xl p-4 max-h-[65vh] overflow-y-auto terminal-scrollbar">
          {activeTab === 'threat'
            ? <ThreatAnalysisView data={data} />
            : <CodeView code={currentCode} />
          }
        </div>
      </main>
    </div>
  )
}
