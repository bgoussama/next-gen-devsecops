// frontend/src/pages/GeneratorPage.tsx
// Générateur IA — saisie du prompt, templates rapides, logs en temps réel
// Phase 8 : appel /api/v1/generate/all + push automatique GitHub

import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bot, Sparkles, Loader2, Terminal, ChevronRight, GitBranch, ShieldCheck } from 'lucide-react'
import { Navbar } from '../components/Navbar'
import { apiGenerateAll } from '../lib/api'

// ─── Templates de prompts rapides ─────────────────────────────────────────────
const TEMPLATES = [
  { label: 'Node.js',          prompt: 'Crée un pipeline CI/CD pour une app Node.js avec tests Jest, ESLint, build Docker multi-stage et déploiement Kubernetes avec rolling updates.' },
  { label: 'Python / FastAPI', prompt: 'Pipeline CI/CD pour FastAPI avec pytest, bandit, safety check, SonarQube, build Docker optimisé et manifests Kubernetes.' },
  { label: 'Java Spring',      prompt: 'Pipeline Jenkins pour Spring Boot avec Maven, JUnit, SonarQube quality gate, build Docker et déploiement K8s avec Helm chart.' },
  { label: 'React Full Stack',  prompt: 'CI/CD complet pour app React + Node.js API avec tests Cypress, build optimisé Vite, Docker multi-stage et déploiement K8s.' },
  { label: 'Django',           prompt: 'Pipeline pour Django avec pytest-django, coverage 80%, Bandit SAST, Docker build et déploiement Kubernetes avec secrets management.' },
]

// ─── Types ────────────────────────────────────────────────────────────────────
interface LogLine {
  id: number
  text: string
  type: 'info' | 'success' | 'error' | 'system'
}

interface ThreatTechnique {
  id: string
  name: string
  status: 'PROTECTED' | 'AT_RISK' | 'UNKNOWN'
  description: string
  evidence: string
}

interface ThreatSnapshot {
  score: number
  riskLevel: string
  techniques: ThreatTechnique[]
}

const LOG_COLORS: Record<string, string> = {
  info:    'text-cyan-300',
  success: 'text-green-400',
  error:   'text-red-400',
  system:  'text-muted-foreground',
}

function delay(ms: number) {
  return new Promise<void>(r => setTimeout(r, ms))
}

function scoreBadgeClass(score: number) {
  if (score > 80) return 'border-success/30 bg-success/10 text-success'
  if (score >= 60) return 'border-warning/30 bg-warning/10 text-warning'
  return 'border-destructive/30 bg-destructive/10 text-destructive'
}

function techniqueStatusClass(status: ThreatTechnique['status']) {
  if (status === 'PROTECTED') return 'text-success'
  if (status === 'AT_RISK') return 'text-destructive'
  return 'text-warning'
}

// ─── Composant principal ───────────────────────────────────────────────────────
export default function GeneratorPage() {
  const navigate = useNavigate()
  const [prompt, setPrompt]       = useState('')
  const [loading, setLoading]     = useState(false)
  const [logs, setLogs]           = useState<LogLine[]>([])
  const [success, setSuccess]     = useState(false)
  const [githubUrl, setGithubUrl] = useState('')
  const [threat, setThreat]       = useState<ThreatSnapshot | null>(null)
  const logRef = useRef<HTMLDivElement>(null)
  const logId  = useRef(0)

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [logs])

  const addLog = (text: string, type: LogLine['type'] = 'info') => {
    setLogs(prev => [...prev, { id: logId.current++, text, type }])
  }

  const handleGenerate = async () => {
    if (!prompt.trim()) return
    setLoading(true)
    setLogs([])
    setSuccess(false)
    setGithubUrl('')
    setThreat(null)

    // ── Logs visibles par l'utilisateur — simples et professionnels ──
    // Aucune mention de Groq, des couches de sécurité ou de l'architecture interne
    addLog('[...] Analyse de votre description...', 'system')
    await delay(350)
    addLog('[...] Connexion au moteur de génération...', 'info')
    await delay(450)
    addLog('[...] Validation de la requête...', 'system')
    await delay(350)
    addLog('[...] Génération des fichiers en cours...', 'info')
    await delay(500)
    addLog('[...] Jenkinsfile · Terraform · Dockerfile · Kubernetes...', 'system')

    try {
      const data = await apiGenerateAll(prompt)

      if (!data.success) {
        addLog(`[ERREUR] ${data.error_message}`, 'error')
        return
      }

      addLog('[OK] Fichiers générés avec succès !', 'success')
      addLog(`[INFO] ${data.tokens_used?.toLocaleString('fr-FR') || 0} tokens traités`, 'info')

      if (data.github_branch_url) {
        addLog('[OK] Fichiers sauvegardés dans le référentiel', 'success')
        setGithubUrl(data.github_branch_url)
      }

      const threatSnapshot: ThreatSnapshot = {
        score: data.threat_score || 0,
        riskLevel: data.threat_risk_level || 'UNKNOWN',
        techniques: data.threat_techniques || [],
      }
      setThreat(threatSnapshot)
      addLog(`[OK] Score MITRE ATT&CK : ${threatSnapshot.score}/100 (${threatSnapshot.riskLevel})`, 'success')

      addLog('[OK] Prêt — cliquez sur "Voir dans l\'éditeur"', 'success')

      // ── Stocker les 4 artefacts dans localStorage pour l'éditeur ──
      const generation = {
        id:                `gen_${Date.now()}`,
        prompt,
        jenkinsfile:       data.jenkinsfile        || '',
        terraform:         data.terraform          || '',
        dockerfile:        data.dockerfile         || '',
        k8s_manifest:      data.k8s_manifest       || '',
        tokens_used:       data.tokens_used        || 0,
        github_branch_url: data.github_branch_url  || '',
        threat_score:      data.threat_score       || 0,
        threat_risk_level: data.threat_risk_level  || '',
        threat_techniques: data.threat_techniques  || [],
        threat_recommendations: data.threat_recommendations || [],
        threat_summary:    data.threat_summary     || '',
        created_at:        new Date().toISOString(),
      }
      localStorage.setItem('lastGeneration', JSON.stringify(generation))

      // ── Ajouter à l'historique local (50 entrées max) ──
      const history: object[] = JSON.parse(
        localStorage.getItem('generationHistory') || '[]'
      )
      history.unshift({
        id:                generation.id,
        prompt:            prompt.substring(0, 100),
        created_at:        generation.created_at,
        tokens_used:       data.tokens_used        || 0,
        github_branch_url: data.github_branch_url  || '',
        status:            'success',
      })
      localStorage.setItem(
        'generationHistory',
        JSON.stringify(history.slice(0, 50))
      )

      setSuccess(true)

    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Erreur inconnue'
      addLog(`[ERREUR] ${msg}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="mx-auto max-w-5xl px-4 py-8">

        {/* En-tête */}
        <div className="flex items-center gap-3 mb-8">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
            <Bot className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Générateur IA</h1>
            <p className="text-sm text-muted-foreground">
              Décrivez votre infrastructure — 4 artefacts générés automatiquement
            </p>
          </div>
        </div>

        {/* Templates rapides */}
        <div className="mb-6">
          <p className="text-xs font-medium text-muted-foreground mb-2.5">
            Templates rapides :
          </p>
          <div className="flex flex-wrap gap-2">
            {TEMPLATES.map(t => (
              <button
                key={t.label}
                onClick={() => { setPrompt(t.prompt); setSuccess(false); setThreat(null) }}
                className="rounded-lg border border-border bg-secondary px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:border-primary/30 transition-colors"
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* Zone de saisie */}
        <div className="glass-card rounded-xl p-4 mb-4">
          <textarea
            value={prompt}
            onChange={e => { setPrompt(e.target.value); setSuccess(false); setThreat(null) }}
            placeholder="Ex: Crée un pipeline CI/CD pour une application Python FastAPI avec tests pytest, analyse SonarQube, build Docker multi-stage et déploiement Kubernetes..."
            rows={5}
            disabled={loading}
            className="w-full min-h-[120px] resize-none bg-transparent text-sm placeholder:text-muted-foreground/50 focus:outline-none disabled:opacity-60"
          />
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-border">
            <p className="text-xs text-muted-foreground">
              {prompt.length > 0
                ? `${prompt.length} caractères`
                : 'Décrivez votre besoin en détail'}
            </p>
            <button
              onClick={handleGenerate}
              disabled={loading || !prompt.trim()}
              className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50 hover:bg-primary/90 transition-colors"
            >
              {loading
                ? <><Loader2 className="h-4 w-4 animate-spin" /> Génération...</>
                : <><Sparkles className="h-4 w-4" /> Générer</>
              }
            </button>
          </div>
        </div>

        {/* Terminal de logs */}
        {logs.length > 0 && (
          <div className="glass-card rounded-xl mb-6 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-secondary/30">
              <Terminal className="h-3.5 w-3.5 text-primary" />
              <span className="text-xs font-medium text-muted-foreground">
                Progression
              </span>
              {loading && (
                <Loader2 className="h-3 w-3 text-primary animate-spin ml-auto" />
              )}
            </div>
            <div
              ref={logRef}
              className="p-4 h-48 overflow-y-auto font-mono text-xs space-y-1"
            >
              {logs.map(line => (
                <p key={line.id} className={LOG_COLORS[line.type]}>
                  <span className="text-muted-foreground/50 mr-2 select-none">
                    {'>'}
                  </span>
                  {line.text}
                </p>
              ))}
            </div>
          </div>
        )}

        {/* CTA après génération réussie */}
        {success && (
          <div className="glass-card rounded-xl p-6 text-center">
            <div className="flex items-center justify-center gap-2 text-green-400 mb-2">
              <Sparkles className="h-5 w-5" />
              <span className="font-semibold">
                Fichiers générés avec succès !
              </span>
            </div>
            <p className="text-sm text-muted-foreground mb-4">
              Jenkinsfile, Terraform, Dockerfile et Kubernetes manifest sont prêts.
            </p>

            {threat && (
              <div className="mb-5 rounded-lg border border-border bg-secondary/30 p-4 text-left">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-primary" />
                    <span className="text-sm font-semibold">MITRE ATT&CK</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${scoreBadgeClass(threat.score)}`}>
                      Score {threat.score}/100
                    </span>
                    <span className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">
                      Risque {threat.riskLevel}
                    </span>
                  </div>
                </div>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  {threat.techniques.map(technique => (
                    <div key={technique.id} className="rounded-md border border-border/70 bg-background/40 p-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-medium">{technique.id} · {technique.name}</span>
                        <span className={`text-[11px] font-semibold ${techniqueStatusClass(technique.status)}`}>
                          {technique.status}
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] text-muted-foreground">{technique.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {githubUrl && (
              <a
                href={githubUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-2 text-sm text-green-400 hover:bg-green-500/20 transition-colors mb-4 mr-3"
              >
                <GitBranch className="h-4 w-4" />
                Voir sur GitHub
              </a>
            )}

            <button
              onClick={() => navigate('/editor')}
              className="inline-flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              Voir dans l'éditeur <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        )}

      </main>
    </div>
  )
}
