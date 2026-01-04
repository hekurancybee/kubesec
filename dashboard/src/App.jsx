import { Navigate, Route, Routes, useLocation } from "react-router-dom"
import AppShell from "./layouts/AppShell"
import Overview from "./pages/Overview"
import Workloads from "./pages/Workloads"
import PolicyAudit from "./pages/PolicyAudit"
import Audit from "./pages/Audit"
import Login from "./pages/Login"

function ProtectedRoute({ children }) {
  const token = sessionStorage.getItem("kubesec_token")
  const location = useLocation()

  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        }
      >
        <Route path="/" element={<Overview />} />
        <Route path="/workloads" element={<Workloads />} />
        <Route path="/policies" element={<PolicyAudit />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
