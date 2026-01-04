import { useState, useEffect, useRef } from "react"
import { Card, CardInner } from "../components/ui/Card"
import { Pill } from "../components/ui/Pill"
import { EmptyState } from "../components/ui/EmptyState"
import { Button } from "../components/ui/Button"
import { formatDateTime } from "../lib/format"
import { fetchGlobalAudit } from "../lib/api"
import { Shield, User, Clock, Info, Download, ChevronDown } from "lucide-react"

function tone(action) {
  if (action === "ALLOW" || action === "LEARN") return "good"
  if (action === "BLOCK" || action === "DENY") return "bad"
  if (action === "REVOKE" || action === "DELETE") return "warning"
  return "neutral"
}

export default function Audit() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showExport, setShowExport] = useState(false)
  const dropdownRef = useRef(null)

  useEffect(() => {
    fetchGlobalAudit()
      .then(setLogs)
      .catch((err) => {
        console.error(err)
        setError(err.message)
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setShowExport(false)
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [])

  async function handleExport(format) {
    try {
      setShowExport(false)
      let content = ""
      let mimeType = ""
      let filename = `kubesec-global-audit-${new Date().toISOString().split('T')[0]}.${format}`

      if (format === "json") {
        content = JSON.stringify(logs, null, 2)
        mimeType = "application/json"
      } else if (format === "csv") {
        const headers = "timestamp,user_id,workload_key,action,syscall_name,argument,reason\n"
        const rows = (logs || []).map(log =>
          `"${log.timestamp}","${log.user_id}","${log.workload_key}","${log.action}","${log.syscall_name}","${log.argument || ""}",${JSON.stringify(log.reason || "")}`
        ).join("\n")
        content = headers + rows
        mimeType = "text/csv"
      }

      const blob = new Blob([content], { type: mimeType })
      const url = URL.createObjectURL(blob)
      const link = document.createElement("a")
      link.href = url
      link.download = filename
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error("Export failed:", err)
    }
  }

  if (loading) {
    return (
      <div className="stack items-center justify-center" style={{ height: "400px" }}>
        <div className="anim-spin subtle" style={{ width: "2rem", height: "2rem" }}>
          <Shield size={32} />
        </div>
        <div className="dim italic mt-2">Loading governance audit logs...</div>
      </div>
    )
  }

  if (error) {
    return (
      <Card tone="bad">
        <CardInner>
          <div className="stack items-center py-8">
            <Info className="dim mb-4" size={48} />
            <div className="bold large text-bad">Failed to load audit logs</div>
            <div className="dim">{error}</div>
          </div>
        </CardInner>
      </Card>
    )
  }

  return (
    <div className="stack" style={{ gap: "1.25rem" }}>
      <div className="row between items-start">
        <div className="stack">
          <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 900 }}>Governance Audit Log</h1>
          <div className="dim small">Consolidated record of all policy adjustments and manual interventions across the cluster.</div>
        </div>

        <div className="row" style={{ gap: "0.75rem", position: 'relative' }} ref={dropdownRef}>
          <span className="pill small" style={{ height: 'fit-content', marginTop: '4px' }}>Retention: 90d</span>
          <div className="stack" style={{ position: 'relative' }}>
            <Button
              variant="ghost"
              onClick={() => setShowExport(!showExport)}
              disabled={logs.length === 0}
            >
              <Download size={16} /> Export <ChevronDown size={14} />
            </Button>
            {showExport && (
              <div
                className="stack anim-fade-in"
                style={{
                  position: 'absolute',
                  top: '100%',
                  right: 0,
                  zIndex: 100,
                  marginTop: '8px',
                  padding: '4px',
                  minWidth: '160px',
                  background: '#1a1d21', // Dark solid background
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5)',
                  backdropFilter: 'blur(8px)'
                }}
              >
                <button className="btn btn-ghost items-start py-2 px-3 row" onClick={() => handleExport('csv')}>
                  <span className="bold x-small">Export as CSV</span>
                </button>
                <button className="btn btn-ghost items-start py-2 px-3 row" onClick={() => handleExport('json')}>
                  <span className="bold x-small">Export as JSON</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {!logs || logs.length === 0 ? (
        <EmptyState
          title="No audit entries found"
          description="All policy changes, manual approvals, and revocations will appear here for compliance review."
        />
      ) : (
        <div className="stack" style={{ gap: "0.75rem" }}>
          {logs.map((log, idx) => (
            <Card key={`${log.timestamp}-${idx}`}>
              <CardInner>
                <div className="row between" style={{ alignItems: "flex-start" }}>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="row items-center" style={{ gap: "0.75rem", flexWrap: "wrap" }}>
                      <Pill tone={tone(log.action)}>{log.action}</Pill>
                      <span className="bold x-large">{log.syscall_name}</span>
                      <span className="dim small">on</span>
                      <span className="bold accent" style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                        {log.workload_key}
                      </span>
                    </div>

                    <div
                      className="mono x-small"
                      style={{
                        marginTop: "0.75rem",
                        padding: "0.75rem",
                        borderRadius: 8,
                        background: "rgba(0,0,0,0.25)",
                        border: "1px solid rgba(255,255,255,0.08)",
                        maxHeight: "100px",
                        overflow: "auto"
                      }}
                    >
                      {log.argument || "(no argument)"}
                    </div>

                    <div className="row between mt-3">
                      <div className="row items-center dim x-small" style={{ gap: '0.4rem' }}>
                        <Info size={12} />
                        Reason: <span className="text-1 bold ml-1">{log.reason}</span>
                      </div>
                      <div className="row items-center dim x-small" style={{ gap: '0.4rem' }}>
                        <User size={12} color="var(--accent)" />
                        By: <span className="text-1 bold ml-1">{log.user_id}</span>
                      </div>
                    </div>
                  </div>

                  <div className="stack items-end ml-4" style={{ flexShrink: 0 }}>
                    <div className="row items-center dim x-small" style={{ gap: '0.4rem' }}>
                      <Clock size={12} />
                      {formatDateTime(log.timestamp)}
                    </div>
                  </div>
                </div>
              </CardInner>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
