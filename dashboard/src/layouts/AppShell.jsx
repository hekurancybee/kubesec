import { createElement } from "react"
import { NavLink, Outlet, useLocation } from "react-router-dom"
import {
  Activity,
  Blocks,
  Brain,
  Cuboid,
  Gauge,
  Shield,
  Siren,
  SlidersHorizontal,
  User,
  LogOut,
} from "lucide-react"
import { IconButton } from "../components/ui/Button"
import { useEffect, useState } from "react"
import { fetchStatsSummary, logout } from "../lib/api"

function NavItem({ to, icon: Icon, label, sublabel, right }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => (isActive ? "active" : "")}
      end
    >
      <span className="nav-left">
        {createElement(Icon, { size: 18, style: { flex: "0 0 auto" } })}
        <span style={{ minWidth: 0 }}>
          <div className="nav-label">{label}</div>
          {sublabel ? <div className="nav-sub">{sublabel}</div> : null}
        </span>
      </span>
      {right ? <span className="pill">{right}</span> : null}
    </NavLink>
  )
}

function routeTitle(pathname) {
  if (pathname === "/") return "Overview"
  if (pathname.startsWith("/workloads")) return "Workloads"
  if (pathname.startsWith("/detections")) return "Detections"
  if (pathname.startsWith("/policies")) return "Policy Audit"
  if (pathname.startsWith("/audit")) return "Audit"
  return "KubeSec"
}

function routeSubtitle(pathname) {
  if (pathname === "/") return "Posture, attacks, and feedback loops"
  if (pathname.startsWith("/workloads")) return "Fleet inventory • training & enforcement"
  if (pathname.startsWith("/detections")) return "Grouped alerts inbox + live syscall stream"
  if (pathname.startsWith("/policies")) return "Audit & manage auto-learned baselines"
  if (pathname.startsWith("/audit")) return "Traceability for security and policy actions"
  return ""
}

export default function AppShell() {
  const { pathname } = useLocation()
  const title = routeTitle(pathname)
  const subtitle = routeSubtitle(pathname)

  const [summary, setSummary] = useState({ clusterName: "k8s-cluster", totalEvents: 0, blockedEvents: 0, learnedEvents: 0 })

  useEffect(() => {
    async function load() {
      try {
        const s = await fetchStatsSummary()
        setSummary(s)
      } catch (err) {
        console.error("Failed to fetch cluster summary:", err)
      }
    }
    load()
    const interval = setInterval(load, 30000) // Poll every 30s for the shell
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" />
          <div style={{ minWidth: 0 }}>
            <div className="brand-title">KubeSec</div>
            <div className="nav-sub">Workload Protection</div>
          </div>
        </div>

        <div className="stack" style={{ gap: "0.75rem" }}>
          <div className="pill" style={{ justifyContent: "space-between" }}>
            <span className="row" style={{ gap: "0.5rem" }}>
              <Shield size={16} /> Cluster
            </span>
            <span style={{ color: "var(--text-1)", fontWeight: 700 }}>{summary.clusterName}</span>
          </div>

          <nav className="nav" aria-label="Primary">
            <NavItem to="/" icon={Gauge} label="Overview" sublabel="SOC summary" />
            <NavItem to="/workloads" icon={Cuboid} label="Workloads" sublabel="Train & enforce" />
            <NavItem to="/policies" icon={Brain} label="Policy Audit" sublabel="Review baselines" />
            <NavItem to="/audit" icon={Activity} label="Audit" sublabel="Changes & actions" />
          </nav>
        </div>

        <div style={{ marginTop: "auto" }}>
          <div
            className="card"
            style={{ padding: "1rem", borderRadius: "14px", background: "rgba(255,255,255,0.03)" }}
          >
            <div className="row between" style={{ marginBottom: "0.6rem" }}>
              <div style={{ fontWeight: 800 }}>Enforcement</div>
              <span className="pill pill-accent">Active</span>
            </div>
            <div className="dim" style={{ fontSize: "0.85rem" }}>
              eBPF policy engine enabled. False positives can be routed to supervised learning.
            </div>
          </div>

          <div className="row" style={{ marginTop: "0.75rem", justifyContent: "space-between" }}>
            <span className="subtle" style={{ fontSize: "0.8rem" }}>
              v0.1.0-alpha
            </span>
            <span className="subtle" style={{ fontSize: "0.8rem" }}>
              SOC
            </span>
          </div>
        </div>
      </aside>

      <div className="content">
        <div className="topbar">
          <div>
            <div style={{ fontWeight: 950, fontSize: "1.35rem", letterSpacing: "-0.02em" }}>{title}</div>
            {subtitle ? (
              <div className="dim" style={{ fontSize: "0.9rem", marginTop: "0.25rem" }}>
                {subtitle}
              </div>
            ) : null}
          </div>

          <div className="row" style={{ gap: "1rem" }}>
            <div className="row items-center" style={{ gap: "0.5rem", padding: "0 0.5rem", borderRight: "1px solid var(--border)", marginRight: "0.5rem" }}>
              <span className="pill small secondary">{sessionStorage.getItem('kubesec_user') || 'Admin'}</span>
              <IconButton aria-label="Logout" title="Logout" onClick={logout} variant="ghost" style={{ color: 'var(--bad)' }}>
                <LogOut size={18} />
              </IconButton>
            </div>
            <div className="row" style={{ gap: "0.5rem" }}>
              <span className="pill">Nodes: {summary.nodeCount || 0}</span>
              <span className="pill">Namespaces: {summary.namespaceCount || 0}</span>
              <IconButton aria-label="Filters" title="Filters">
                <SlidersHorizontal size={18} />
              </IconButton>
              <IconButton aria-label="Blocks" title="Blocks">
                <Blocks size={18} />
              </IconButton>
            </div>
          </div>
        </div>

        <Outlet />
      </div>
    </div>
  )
}
