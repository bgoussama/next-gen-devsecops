// frontend/src/lib/api.ts
// Service centralisé pour tous les appels HTTP vers le backend FastAPI
// Toutes les fonctions fetch() passent par ce fichier

const BASE_URL = 'http://localhost:8000'

// ----------------------------------------------------------------
// GESTION DU TOKEN JWT
// Stocké dans localStorage — lu à chaque requête authentifiée
// ----------------------------------------------------------------
export const tokenService = {
  get:       ()          => localStorage.getItem('token'),
  set:       (t: string) => localStorage.setItem('token', t),
  remove:    ()          => localStorage.removeItem('token'),
  getRole:   ()          => localStorage.getItem('role'),
  setRole:   (r: string) => localStorage.setItem('role', r),
  getUserId: ()          => localStorage.getItem('user_id'),
  setUserId: (id:string) => localStorage.setItem('user_id', id),
}

// ----------------------------------------------------------------
// HELPER — Requête authentifiée avec JWT
// Ajoute automatiquement le header Authorization à chaque appel
// Redirige vers /login si le token est expiré (401)
// ----------------------------------------------------------------
async function authFetch(url: string, options: RequestInit = {}) {
  const token = tokenService.get()

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> || {}),
  }

  const response = await fetch(url, { ...options, headers })

  // [SECURITY] Token expiré ou invalide → déconnecter l'utilisateur
  if (response.status === 401) {
    tokenService.remove()
    tokenService.setRole('')
    tokenService.setUserId('')
    window.location.href = '/login'
    throw new Error('Session expirée. Reconnecte-toi.')
  }

  return response
}

// ----------------------------------------------------------------
// AUTH — Connexion
// ----------------------------------------------------------------

export async function apiLogin(email: string, password: string) {
  const response = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })

  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.detail || 'Email ou mot de passe incorrect')
  }

  // Stocker le token et les infos utilisateur
  tokenService.set(data.access_token)
  tokenService.setRole(data.role)
  tokenService.setUserId(data.user_id)

  return data
}

export function apiLogout() {
  tokenService.remove()
  tokenService.setRole('')
  tokenService.setUserId('')
  window.location.href = '/login'
}

// ----------------------------------------------------------------
// GÉNÉRATION — Un seul Jenkinsfile (Couches 1+2+3)
// Utilisé pour la génération simple sans push GitHub
// ----------------------------------------------------------------

export async function apiGenerate(prompt: string) {
  const response = await authFetch(`${BASE_URL}/api/v1/generate`, {
    method: 'POST',
    body: JSON.stringify({ prompt }),
  })

  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.detail || 'Erreur lors de la génération')
  }

  return data
}

// ----------------------------------------------------------------
// GÉNÉRATION COMPLÈTE — 4 artefacts + push GitHub automatique
//
// [WHY cette fonction et pas apiGenerate]
// apiGenerate → POST /api/v1/generate → 1 Jenkinsfile, pas de GitHub
// apiGenerateAll → POST /api/v1/generate/all → 4 artefacts + branche GitHub
//
// Retourne :
// {
//   success: boolean,
//   jenkinsfile: string,
//   terraform: string,
//   dockerfile: string,
//   k8s_manifest: string,
//   tokens_used: number,
//   github_branch_url: string  ← URL de la branche créée sur GitHub
// }
// ----------------------------------------------------------------

export async function apiGenerateAll(prompt: string) {
  const response = await authFetch(`${BASE_URL}/api/v1/generate/all`, {
    method: 'POST',
    body: JSON.stringify({ prompt }),
  })

  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.detail || 'Erreur lors de la génération')
  }

  return data
}

// ----------------------------------------------------------------
// HISTORIQUE
// ----------------------------------------------------------------

export async function apiGetHistory() {
  const response = await authFetch(`${BASE_URL}/api/v1/history`)
  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.detail || 'Erreur lors du chargement de l\'historique')
  }

  return data
}

export async function apiGetPipelineReports() {
  const response = await authFetch(`${BASE_URL}/api/v1/pipeline/reports`)
  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.detail || 'Erreur lors du chargement des rapports Jenkins')
  }

  return data
}

// ----------------------------------------------------------------
// HEALTH CHECK — État du backend
// Public — pas de JWT requis
// ----------------------------------------------------------------

export async function apiHealthCheck(): Promise<boolean> {
  try {
    const response = await fetch(`${BASE_URL}/health`)
    return response.ok
  } catch {
    return false
  }
}
