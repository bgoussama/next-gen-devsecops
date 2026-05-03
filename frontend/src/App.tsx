// Router principal — routes publiques et routes protégées par JWT
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import LoginPage      from './pages/LoginPage'
import DashboardPage  from './pages/DashboardPage'
import GeneratorPage  from './pages/GeneratorPage'
import EditorPage     from './pages/EditorPage'
import HistoryPage    from './pages/HistoryPage'
import SettingsPage   from './pages/SettingsPage'
import MonitoringPage from './pages/MonitoringPage'

// Redirige vers /login si aucun token valide en localStorage
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Redirection racine → générateur */}
        <Route path="/" element={<Navigate to="/generator" replace />} />

        {/* Route publique */}
        <Route path="/login" element={<LoginPage />} />

        {/* Routes protégées */}
        <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
        <Route path="/generator" element={<ProtectedRoute><GeneratorPage /></ProtectedRoute>} />
        <Route path="/editor"    element={<ProtectedRoute><EditorPage /></ProtectedRoute>} />
        <Route path="/history"    element={<ProtectedRoute><HistoryPage /></ProtectedRoute>} />
        <Route path="/monitoring" element={<ProtectedRoute><MonitoringPage /></ProtectedRoute>} />
        <Route path="/settings"   element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />

        {/* Fallback */}
        <Route path="*" element={<Navigate to="/generator" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
