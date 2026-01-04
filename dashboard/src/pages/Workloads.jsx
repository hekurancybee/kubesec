import { useEffect, useMemo, useState } from "react"
import { ArrowDownUp, Filter, Search } from "lucide-react"
import { Card, CardInner } from "../components/ui/Card"
import { Pill } from "../components/ui/Pill"
import { Button } from "../components/ui/Button"
import { Drawer } from "../components/ui/Drawer"
import { EmptyState } from "../components/ui/EmptyState"
import { Progress } from "../components/ui/Progress"
import { formatDateTime } from "../lib/format"
import { fetchWorkloads, setWorkloadMode } from "../lib/api"
import { mockWorkloads } from "../mockData"
import { useToast } from "../components/ui/Toast"

function statusTone(status) {
  if (status === "enforcing") return "good"
  if (status === "learning") return "info"
  if (status === "observing") return "warn"
  if (status === "unmonitored") return "neutral"
  return "neutral"
}

function compare(a, b) {
  if (typeof a === "number" && typeof b === "number") return a - b
  return String(a ?? "").localeCompare(String(b ?? ""))
}

export default function Workloads() {
  const [query, setQuery] = useState("")
  const [status, setStatus] = useState("all")
  const [sortKey, setSortKey] = useState("name")
  const [sortDir, setSortDir] = useState("asc")
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState(null)
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [updating, setUpdating] = useState(false)
  const toast = useToast()

  async function load() {
    try {
      setLoading(true)
      const res = await fetchWorkloads()
      setData(res)
      setError(null)
      return res
    } catch (err) {
      console.error(err)
      setError(err.message)
      setData(mockWorkloads)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  async function handleModeChange(workloadKey, mode) {
    try {
      setUpdating(true)
      await setWorkloadMode(workloadKey, mode)
      toast.push({
        title: "Mode Updated",
        description: `${workloadKey} is now in ${mode} mode.`,
        tone: "good",
      })
      const freshData = await load()
      // Update selected item if it's the one we just changed
      if (selected && selected.id === workloadKey) {
        const updated = freshData.find(w => w.id === workloadKey)
        if (updated) setSelected(updated)
      } else {
        setSelected(null)
      }
    } catch (err) {
      toast.push({
        title: "Update Failed",
        description: err.message,
        tone: "bad",
      })
    } finally {
      setUpdating(false)
    }
  }

  const pageSize = 10

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim()
    return data.filter((w) => {
      const matchQ = !q || w.name.toLowerCase().includes(q) || w.namespace.toLowerCase().includes(q)
      const matchS = status === "all" || w.status === status
      return matchQ && matchS
    })
  }, [data, query, status])

  const sorted = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1
    return filtered
      .slice()
      .sort((a, b) => dir * compare(a[sortKey], b[sortKey]))
  }, [filtered, sortKey, sortDir])

  const total = sorted.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const safePage = Math.min(page, totalPages)

  const rows = useMemo(() => {
    const start = (safePage - 1) * pageSize
    return sorted.slice(start, start + pageSize)
  }, [sorted, safePage])

  function toggleSort(nextKey) {
    if (sortKey === nextKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"))
      return
    }
    setSortKey(nextKey)
    setSortDir("asc")
  }

  function resetPage() {
    setPage(1)
  }

  return (
    <div className="stack" style={{ gap: "1.25rem" }}>
      <div className="row between" style={{ alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
        <span className="pill">Total: {total.toLocaleString()}</span>
      </div>

      <Card>
        <CardInner>
          <div className="row between" style={{ gap: "1rem", flexWrap: "wrap" }}>
            <div className="row" style={{ gap: "0.5rem", flex: "1 1 360px" }}>
              <div className="pill" style={{ padding: "0.45rem 0.6rem" }}>
                <Search size={16} />
              </div>
              <input
                className="input"
                placeholder="Search workloads by name or namespace…"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value)
                  resetPage()
                }}
              />
            </div>

            <div className="row" style={{ gap: "0.5rem" }}>
              <span className="pill" style={{ padding: "0.45rem 0.6rem" }}>
                <Filter size={16} />
              </span>
              <select
                className="select"
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value)
                  resetPage()
                }}
              >
                <option value="all">All statuses</option>
                <option value="learning">Learning</option>
                <option value="observing">Observing</option>
                <option value="enforcing">Enforcing</option>
                <option value="unmonitored">Unmonitored</option>
              </select>
            </div>

            <div className="row" style={{ gap: "0.5rem" }}>
              <Button size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))}>
                Prev
              </Button>
              <span className="pill">
                Page {safePage} / {totalPages}
              </span>
              <Button size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
                Next
              </Button>
            </div>
          </div>
        </CardInner>
      </Card>

      {rows.length === 0 ? (
        <EmptyState title="No workloads match" description="Try a different query or filter." />
      ) : (
        <Card>
          <div style={{ overflow: "hidden", borderRadius: "var(--r-lg)" }}>
            <table className="table">
              <thead>
                <tr>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("name")}>
                    <span className="row" style={{ gap: "0.4rem" }}>
                      Workload <ArrowDownUp size={14} />
                    </span>
                  </th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("namespace")}>
                    <span className="row" style={{ gap: "0.4rem" }}>
                      Namespace <ArrowDownUp size={14} />
                    </span>
                  </th>
                  <th>Kind</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("status")}>
                    <span className="row" style={{ gap: "0.4rem" }}>
                      Status <ArrowDownUp size={14} />
                    </span>
                  </th>
                  <th style={{ width: 280 }}>Learning</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("policyVersion")}>
                    <span className="row" style={{ gap: "0.4rem" }}>
                      Policy <ArrowDownUp size={14} />
                    </span>
                  </th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("lastSync")}>
                    <span className="row" style={{ gap: "0.4rem" }}>
                      Last sync <ArrowDownUp size={14} />
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((w) => (
                  <tr
                    key={w.id}
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelected(w)}
                    onKeyDown={(ev) => {
                      if (ev.key === "Enter") setSelected(w)
                    }}
                    tabIndex={0}
                  >
                    <td>
                      <div style={{ fontWeight: 950 }}>{w.name}</div>
                      <div className="subtle" style={{ fontSize: "0.8rem", marginTop: "0.15rem" }}>
                        Replicas: {w.replicas} • Hash: <span className="mono">{w.templateHash}</span>
                      </div>
                    </td>
                    <td className="dim">{w.namespace}</td>
                    <td className="dim">{w.kind}</td>
                    <td>
                      <Pill tone={statusTone(w.status)}>{w.status}</Pill>
                    </td>
                    <td>
                      <div className="row" style={{ gap: "0.75rem" }}>
                        <div style={{ width: 170 }}>
                          <Progress value={w.trainingProgress} />
                        </div>
                        <div style={{ fontWeight: 900 }}>{w.trainingProgress}%</div>
                      </div>
                    </td>
                    <td className="dim" style={{ fontWeight: 900 }}>
                      {w.policyVersion}
                    </td>
                    <td className="dim">{formatDateTime(w.lastSync)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <Drawer
        open={Boolean(selected)}
        title={selected ? selected.name : ""}
        subtitle={selected ? `${selected.namespace} • ${selected.kind}` : ""}
        onClose={() => setSelected(null)}
      >
        {selected ? (
          <div className="stack" style={{ gap: "1rem" }}>
            <div className="row between">
              <Pill tone={statusTone(selected.status)}>{selected.status}</Pill>
              <span className="pill">Policy {selected.policyVersion}</span>
            </div>

            <Card>
              <CardInner>
                <div style={{ fontWeight: 900, marginBottom: "0.5rem" }}>Summary (mock)</div>
                <div className="dim" style={{ fontSize: "0.9rem" }}>
                  In the real product this drawer would show syscall profile diffs, recent blocks, and policy history.
                </div>

                <div className="stack" style={{ gap: "0.5rem", marginTop: "0.9rem" }}>
                  <div className="row between">
                    <span className="subtle">Template hash</span>
                    <span className="mono" style={{ color: "var(--accent)", fontWeight: 900 }}>
                      {selected.templateHash}
                    </span>
                  </div>
                  <div className="row between">
                    <span className="subtle">Mode</span>
                    <span style={{ fontWeight: 900 }}>{selected.dryRun ? "Dry-run" : "Active"}</span>
                  </div>
                  <div className="row between">
                    <span className="subtle">Training</span>
                    <span style={{ fontWeight: 900 }}>{selected.trainingProgress}%</span>
                  </div>
                  <div className="row between">
                    <span className="subtle">Last sync</span>
                    <span style={{ fontWeight: 900 }}>{formatDateTime(selected.lastSync)}</span>
                  </div>
                </div>
              </CardInner>
            </Card>

            <Card>
              <CardInner>
                <div style={{ fontWeight: 900, marginBottom: "0.5rem" }}>Actions</div>
                <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
                  {selected.status === "unmonitored" ? (
                    <Button
                      variant="primary"
                      onClick={() => handleModeChange(selected.id, "monitor")}
                      disabled={updating}
                    >
                      {updating ? "Updating..." : "Secure & Monitor"}
                    </Button>
                  ) : (
                    <>
                      {selected.status === "learning" ? (
                        <Button
                          variant="primary"
                          onClick={() => handleModeChange(selected.id, "enforcing")}
                          disabled={updating}
                        >
                          {updating ? "Updating..." : "Promote to enforcement"}
                        </Button>
                      ) : (
                        <Button
                          variant="primary"
                          onClick={() => handleModeChange(selected.id, "learning")}
                          disabled={updating}
                        >
                          {updating ? "Updating..." : "Back to learning"}
                        </Button>
                      )}
                      {selected.dryRun ? (
                        <Button
                          onClick={() => handleModeChange(selected.id, "active")}
                          disabled={updating}
                        >
                          {updating ? "Updating..." : "Disable dry-run"}
                        </Button>
                      ) : (
                        <Button
                          onClick={() => handleModeChange(selected.id, "dryrun")}
                          disabled={updating}
                        >
                          {updating ? "Updating..." : "Enable dry-run"}
                        </Button>
                      )}
                      <Button variant="danger" onClick={() => handleModeChange(selected.id, "unmonitor")} disabled={updating}>
                        {updating ? "Stopping..." : "Stop monitoring"}
                      </Button>
                    </>
                  )}
                </div>
              </CardInner>
            </Card>
          </div>
        ) : null}
      </Drawer>

      <div className="subtle" style={{ fontSize: "0.85rem" }}>
        Note: for truly huge tables, the real implementation should use server-side pagination + optional row virtualization.
      </div>
    </div>
  )
}
