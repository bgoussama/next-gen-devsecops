// frontend/src/hooks/useAuth.ts
// Hook d'authentification — lit et écrit le token JWT depuis localStorage

import { useState, useCallback } from 'react'
import { tokenService } from '../lib/api'

export function useAuth() {
  // Initialisation depuis localStorage pour persistance au rechargement
  const [isAuthenticated, setIsAuthenticated] = useState(() => !!tokenService.get())
  const [role, setRole]     = useState(() => tokenService.getRole()   ?? '')
  const [userId, setUserId] = useState(() => tokenService.getUserId() ?? '')

  // Appelé après un login réussi — stocke token + métadonnées
  // [WHY on supprime le paramètre email]
  // tokenService.setEmail n'existe pas dans api.ts
  // L'email est déjà encodé dans le JWT — pas besoin de le stocker séparément
  const handleLogin = useCallback((token: string, r: string, uid: string) => {
    tokenService.set(token)
    tokenService.setRole(r)
    tokenService.setUserId(uid)
    setIsAuthenticated(true)
    setRole(r)
    setUserId(uid)
  }, [])

  // Appelé au logout — efface toutes les données de session
  const handleLogout = useCallback(() => {
    tokenService.remove()
    localStorage.removeItem('role')
    localStorage.removeItem('user_id')
    setIsAuthenticated(false)
    setRole('')
    setUserId('')
  }, [])

  return { isAuthenticated, role, userId, handleLogin, handleLogout }
}