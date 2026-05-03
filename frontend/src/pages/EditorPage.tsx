// Éditeur de pipeline — affichage par onglets, copier/télécharger
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileCode, Copy, Download, Check, Bot } from 'lucide-react'
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
  created_at: string
}

type TabKey = 'jenkinsfile' | 'terraform' | 'dockerfile' | 'kubernetes'

const TABS: { key: TabKey; label: string; filename: string }[] = [
  { key: 'jenkinsfile', label: 'Jenkinsfile',  filename: 'Jenkinsfile' },
  { key: 'terraform',   label: 'Terraform',    filename: 'main.tf' },
  { key: 'dockerfile',  label: 'Dockerfile',   filename: 'Dockerfile' },
  { key: 'kubernetes',  label: 'Kubernetes',   filename: 'k8s-manifest.yaml' },
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

// ─── Composant principal ───────────────────────────────────────────────────────
export default function EditorPage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<TabKey>('jenkinsfile')
  const [copied, setCopied] = useState(false)

  // Lecture de la dernière génération depuis localStorage
  const raw = localStorage.getItem('lastGeneration')
  const data: GenerationData | null = raw ? JSON.parse(raw) : null

  // Construction de la map — champs nouveaux en priorité, fallback sur pipeline_content
  const codeMap: Record<TabKey, string> = {
    jenkinsfile: data?.jenkinsfile || data?.pipeline_content || '',
    terraform:   data?.terraform   || PLACEHOLDER.terraform,
    dockerfile:  data?.dockerfile  || PLACEHOLDER.dockerfile,
    kubernetes:  data?.k8s_manifest || PLACEHOLDER.kubernetes,
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
          <CodeView code={currentCode} />
        </div>
      </main>
    </div>
  )
}
