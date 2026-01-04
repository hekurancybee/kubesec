import { createElement, useEffect, useMemo, useState } from "react"
import { Brain, CheckCircle2, BellDot, Filter, Folder, List, Maximize2, Minimize2, Search, Sparkles, TriangleAlert, Waves, X } from "lucide-react"
import { Card, CardInner } from "./ui/Card"
import { Pill } from "./ui/Pill"
import { Button } from "./ui/Button"
import { Drawer } from "./ui/Drawer"
import { EmptyState } from "./ui/EmptyState"
import { Tabs } from "./ui/Tabs"
import { useToast } from "./ui/Toast"
import { formatTime } from "../lib/format"
import { fetchDetections, approveSyscall, bulkApproveSyscalls } from "../lib/api"
import { mockEvents } from "../mockData"

// No longer using riskTone as we cannot determine risk at this stage.

function actionTone(action) {
  if (action === "blocked") return "bad"
  if (action === "dry-run-blocked" || action === "observed") return "warn"
  if (action === "learned") return "accent"
  return "good"
}

// Signature grouping key: workload + syscall + argument + process
function toSignature(e) {
  return [e.namespace, e.workload, e.syscall, e.argument, e.comm, e.action].join("|\u001F|")
}

const CATEGORIES = {
  Filesystem: [
    "open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat", "chmod", "fchmod",
    "chown", "lchown", "fchown", "mkdir", "mkdirat", "rmdir", "mount", "umount2", "truncate",
    "ftruncate", "fallocate", "utime", "utimes", "utimensat", "newfstatat", "fstatat", "statfs"
  ],
  Network: [
    "socket", "connect", "accept", "accept4", "bind", "listen", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "setsockopt", "getsockopt", "shutdown", "ppoll"
  ],
  Process: [
    "execve", "execveat", "fork", "vfork", "clone", "clone3", "exit", "exit_group", "wait4",
    "waitid", "prctl", "arch_prctl", "capset", "capget"
  ],
  Memory: ["mmap", "munmap", "mprotect", "brk", "mremap", "shmat", "shmdt"],
  IPC: [
    "pipe", "pipe2", "semget", "semop", "semctl", "shmget", "shmat", "shmctl", "msgget",
    "msgsnd", "msgrcv", "msgctl"
  ],
}

function getCategory(syscall) {
  for (const [cat, list] of Object.entries(CATEGORIES)) {
    if (list.includes(syscall)) return cat
  }
  return "Other"
}

/**
 * Reusable panel used on both:
 * - Overview (homepage)
 * - Detections page
 */
export function DetectionsPanel({
  title = "Detections",
  defaultMode = "alerts", // alerts | live
  defaultAction = "blocked", // blocked | learned | allowed | all
  defaultRisk = "all", // high | medium | low | all
  compactHeader = false,
  hideActionFilter = false, // Hide action filter when only one action type available
  windowMinutes = 15,
}) {
  const [mode, setMode] = useState(defaultMode)
  const [action, setAction] = useState(defaultAction)
  const [namespace, setNamespace] = useState("all")
  const [workload, setWorkload] = useState("all")
  const [selectedCategories, setSelectedCategories] = useState(new Set())
  const [isMaximized, setIsMaximized] = useState(false)
  const [selected, setSelected] = useState(null)
  const [data, setData] = useState([])
  const [selectedKeys, setSelectedKeys] = useState(new Set())
  const [loading, setLoading] = useState(true)
  const [approving, setApproving] = useState(false)
  const [isGeneralizing, setIsGeneralizing] = useState(false)
  const [editedArgument, setEditedArgument] = useState("")
  const [cleanupMatched, setCleanupMatched] = useState(true)
  const [forcePrefix, setForcePrefix] = useState(true)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [totalCount, setTotalCount] = useState(0)
  const [search, setSearch] = useState("")
  const toast = useToast()

  function toggleCategory(cat) {
    const next = new Set(selectedCategories)
    if (next.has(cat)) next.delete(cat)
    else next.add(cat)
    setSelectedCategories(next)
  }

  function toggleSelect(key) {
    const next = new Set(selectedKeys)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    setSelectedKeys(next)
  }

  function toggleSelectAll() {
    if (selectedKeys.size === alerts.length) {
      setSelectedKeys(new Set())
    } else {
      setSelectedKeys(new Set(alerts.map((a) => a.key)))
    }
  }

  async function load() {
    try {
      setLoading(true)
      const res = await fetchDetections(windowMinutes, page, pageSize, search, mode === "alerts")

      let items = []
      let total = 0

      // Handle legacy array response vs new paginated response
      if (Array.isArray(res)) {
        items = res
        total = res.length
      } else {
        items = res.data || []
        total = res.meta?.total || 0
      }

      // Map backend fields to frontend expected ones
      const mapped = items.map((d) => ({
        ...d,
        workload: d.workloadKey,
        syscall: d.syscallName,
      }))
      setData(mapped)
      setTotalCount(total)
    } catch (err) {
      console.error("Failed to fetch detections:", err)
      setData(mockEvents) // Fallback
    } finally {
      setLoading(false)
    }
  }

  async function handleApprove() {
    if (!selected) return
    setApproving(true)
    try {
      await approveSyscall(
        selected.workloadKey || selected.workload,
        selected.syscallName || selected.syscall,
        selected.argument,
        selected.isPrefix
      )
      toast.push({
        title: "Policy Authorization",
        description: `Authorized ${selected.syscallName || selected.syscall} for ${selected.workloadKey || selected.workload
          }`,
        tone: "good",
      })
      setSelected(null)
      setIsGeneralizing(false)
      load() // Refresh
    } catch (err) {
      toast.push({
        title: "Approval Failed",
        description: err.message,
        tone: "bad",
      })
    } finally {
      setApproving(false)
    }
  }

  async function handleBulkApprove() {
    if (selectedKeys.size === 0) return
    setApproving(true)

    // Find the alert objects for the selected keys
    const toApprove = alerts.filter((a) => selectedKeys.has(a.key))
    const requests = toApprove.map((a) => ({
      workloadKey: a.workload,
      syscallName: a.syscall,
      argument: a.argument,
    }))

    try {
      await bulkApproveSyscalls(requests)
      toast.push({
        title: "Bulk Authorization",
        description: `Authorized ${requests.length} syscall signatures`,
        tone: "good",
      })
      setSelectedKeys(new Set())
      load() // Refresh
    } catch (err) {
      toast.push({
        title: "Bulk Approval Failed",
        description: err.message,
        tone: "bad",
      })
    } finally {
      setApproving(false)
    }
  }

  const handleGeneralize = async () => {
    if (!selected) return
    setApproving(true)
    try {
      await approveSyscall(
        selected.workloadKey || selected.workload,
        selected.syscallName || selected.syscall,
        editedArgument,
        forcePrefix,
        cleanupMatched
      )
      toast.push({
        title: "Pattern Generalized",
        description: `Created ${forcePrefix ? 'prefix' : 'exact'} rule and cleaned up redundant entries.`,
        tone: "good",
      })
      setSelected(null)
      setIsGeneralizing(false)
      load()
    } catch (err) {
      toast.push({
        title: "Generalization failed",
        description: err.message,
        tone: "bad",
      })
    } finally {
      setApproving(false)
    }
  }

  useEffect(() => {
    if (selected) {
      setEditedArgument(selected.argument)
      setIsGeneralizing(false)
      setForcePrefix(selected.argument.includes('/') || selected.isPrefix)
    }
  }, [selected])

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape" && isMaximized) setIsMaximized(false)
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [isMaximized])

  useEffect(() => {
    // Initial load
    load()

    // Poll every 5 seconds for real-time updates (faster than stats)
    const interval = setInterval(load, 5000)

    return () => clearInterval(interval)
  }, [windowMinutes, page, pageSize, search, mode])

  const rows = useMemo(() => {
    return data
      .filter((e) => {
        const matchAction =
          action === "all" ||
          e.action === action ||
          (action === "blocked" && (e.action === "blocked" || e.action === "dry-run-blocked"))
        const matchNamespace = namespace === "all" || e.namespace === namespace
        const matchWorkload = workload === "all" || e.workload === workload
        const matchCategory =
          selectedCategories.size === 0 || selectedCategories.has(getCategory(e.syscall))
        return matchAction && matchNamespace && matchWorkload && matchCategory
      })
      .slice()
  }, [data, action, namespace, workload, selectedCategories])

  // Derivative key to force re-animation when filters change
  const filterKey = useMemo(() => {
    return [action, namespace, workload, Array.from(selectedCategories).sort().join(",")].join("|")
  }, [action, namespace, workload, selectedCategories])

  const namespaces = useMemo(() => {
    return ["all", ...new Set(data.map((e) => e.namespace))].sort()
  }, [data])

  const workloads = useMemo(() => {
    const list = data
      .filter((e) => namespace === "all" || e.namespace === namespace)
      .map((e) => e.workload)
    return ["all", ...new Set(list)].sort()
  }, [data, namespace])

  const alerts = useMemo(() => {
    const map = new Map()

    for (const e of rows) {
      const key = toSignature(e)
      const prev = map.get(key)
      if (!prev) {
        map.set(key, {
          key,
          namespace: e.namespace,
          workload: e.workload,
          syscall: e.syscall,
          argument: e.argument,
          comm: e.comm,
          action: e.action,
          count: e.count || 1,
          firstSeen: e.firstSeen || e.timestamp,
          lastSeen: e.lastSeen || e.timestamp,
          highestRisk: e.risk,
          sample: e,
          events: [e],
        })
        continue
      }

      prev.count += (e.count || 1)
      if ((e.lastSeen || e.timestamp) > prev.lastSeen) prev.lastSeen = (e.lastSeen || e.timestamp)
      if ((e.firstSeen || e.timestamp) < prev.firstSeen) prev.firstSeen = (e.firstSeen || e.timestamp)
      if (e.risk > prev.highestRisk) prev.highestRisk = e.risk
      prev.events.push(e)
    }

    return Array.from(map.values()).sort((a, b) => {
      return b.lastSeen.localeCompare(a.lastSeen)
    })
  }, [rows])

  const badgeAlerts = alerts.filter((a) => a.action === "blocked").length

  return (
    <div className={`stack ${isMaximized ? "focus-mode" : ""}`} style={{ gap: compactHeader ? "0.75rem" : "1.25rem" }}>
      {compactHeader ? null : (
        <div className="row between" style={{ alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
          <div className="row" style={{ gap: "0.75rem", flexWrap: "wrap" }}>
            <div style={{ fontWeight: 950, fontSize: "1.1rem" }}>{title}</div>
            <span className="pill pill-accent">
              <Sparkles size={14} /> Mock data
            </span>
          </div>
        </div>
      )}

      <div className="row between" style={{ gap: "1rem", flexWrap: "wrap" }}>
        <Tabs
          value={mode}
          onValueChange={setMode}
          items={[
            {
              value: "alerts",
              label: "Alerts",
              icon: createElement(BellDot, { size: 16 }),
              badge: badgeAlerts,
            },
            {
              value: "live",
              label: "Livestream",
              icon: createElement(Waves, { size: 16 }),
            },
          ]}
        />

        <div className="row" style={{ gap: "0.5rem" }}>
          <span className="pill">Tip: open row</span>
          <span className="kbd">Enter</span>
          <span className="kbd">Esc</span>

          <Button
            size="sm"
            variant="ghost"
            onClick={() => setIsMaximized(!isMaximized)}
            style={{ fontSize: "0.8rem", height: "1.6rem", padding: "0 0.5rem", borderRadius: "var(--r-sm)" }}
          >
            {isMaximized ? (
              <>
                <Minimize2 size={12} style={{ marginRight: "0.25rem" }} /> Exit
              </>
            ) : (
              <>
                <Maximize2 size={12} style={{ marginRight: "0.25rem" }} /> Focus
              </>
            )}
          </Button>
        </div>
      </div>

      <Card>
        <CardInner style={{ padding: "0.75rem 1rem" }}>
          <div className="stack" style={{ gap: "0.75rem" }}>
            <div className="row between" style={{ gap: "1rem", flexWrap: "wrap" }}>
              <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
                <div className="filter-group">
                  <span style={{ color: "var(--accent)", padding: "0 0.25rem" }}><Filter size={14} /></span>
                  <select className="select-compact" value={namespace} onChange={(e) => { setNamespace(e.target.value); setWorkload("all") }}>
                    {namespaces.map((n) => (
                      <option key={n} value={n}>{n === "all" ? "All namespaces" : n}</option>
                    ))}
                  </select>
                  <div className="divider-v" />
                  <select className="select-compact" value={workload} onChange={(e) => setWorkload(e.target.value)}>
                    {workloads.map((w) => (
                      <option key={w} value={w}>{w === "all" ? "All workloads" : w}</option>
                    ))}
                  </select>
                </div>

                {!hideActionFilter && (
                  <div className="filter-group">
                    <select className="select-compact" value={action} onChange={(e) => setAction(e.target.value)}>
                      <option value="all">All actions</option>
                      <option value="blocked">Blocked</option>
                      <option value="dry-run-blocked">Observed</option>
                      <option value="learned">Learned</option>
                      <option value="allowed">Allowed</option>
                    </select>
                  </div>
                )}
              </div>

              {/* Search Bar */}
              <div className="row" style={{ flex: 1, minWidth: "200px", position: "relative" }}>
                <Search size={14} style={{ position: "absolute", left: "0.75rem", color: "var(--muted)" }} />
                <input
                  className="input"
                  placeholder="Search..."
                  value={search}
                  onChange={e => { setSearch(e.target.value); setPage(1) }}
                  style={{ width: "100%", fontSize: "0.85rem", padding: "0.35rem 0.75rem 0.35rem 2.2rem", height: "2rem" }}
                />
              </div>

              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setMode(defaultMode)
                  setAction(defaultAction)
                  setNamespace("all")
                  setWorkload("all")
                  setSelectedCategories(new Set())
                }}
                style={{ fontSize: "0.8rem", height: "2rem" }}
              >
                <X size={14} style={{ marginRight: "0.25rem" }} /> Reset Filters
              </Button>
            </div>
            <div className="row" style={{ gap: "0.4rem", flexWrap: "wrap", alignItems: "center" }}>
              <span className="subtle" style={{ fontSize: "0.75rem", marginRight: "0.25rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Behaviors:
              </span>
              {Object.keys(CATEGORIES).map((cat) => {
                const active = selectedCategories.has(cat)
                return (
                  <button
                    key={cat}
                    className={`pill ${active ? "pill-primary" : "pill-ghost"}`}
                    onClick={() => toggleCategory(cat)}
                    style={{
                      fontSize: "0.7rem",
                      padding: "0.15rem 0.6rem",
                      border: "none",
                      cursor: "pointer",
                      borderRadius: "999px",
                      transition: "all 0.2s"
                    }}
                  >
                    {cat}
                  </button>
                )
              })}
              <button
                className={`pill ${selectedCategories.has("Other") ? "pill-primary" : "pill-ghost"}`}
                onClick={() => toggleCategory("Other")}
                style={{
                  fontSize: "0.7rem",
                  padding: "0.15rem 0.6rem",
                  border: "none",
                  cursor: "pointer",
                  borderRadius: "999px"
                }}
              >
                Other
              </button>
            </div>
          </div>
        </CardInner>
      </Card>

      {mode === "alerts" ? (
        alerts.length === 0 ? (
          <EmptyState title="No alerts" description="Try widening filters (Action, Namespace, Workload)." />
        ) : (
          <Card className="anim-filter-flash" key={filterKey}>
            <div style={{ overflow: "hidden", borderRadius: "var(--r-lg)" }}>
              <table className="table">
                <thead>
                  <tr>
                    <th style={{ width: 40 }}>
                      <input
                        type="checkbox"
                        checked={selectedKeys.size === alerts.length && alerts.length > 0}
                        onChange={toggleSelectAll}
                        style={{ cursor: "pointer" }}
                      />
                    </th>
                    <th style={{ width: 80 }}>Count</th>
                    <th style={{ width: 140 }}>Namespace</th>
                    <th style={{ width: 180 }}>Workload</th>
                    <th style={{ width: 120 }}>Syscall</th>
                    <th style={{ width: 120 }}>Process</th>
                    <th>Argument</th>
                    <th style={{ width: 120 }}>Action</th>
                    <th style={{ width: 140 }}>Last seen</th>
                  </tr>
                </thead>
                <tbody style={{ verticalAlign: "top" }}>
                  {alerts.map((a) => (
                    <tr
                      key={a.key}
                      className="stagger-in"
                      style={{ cursor: "pointer", background: selectedKeys.has(a.key) ? "rgba(183, 255, 42, 0.05)" : undefined }}
                      onClick={(e) => {
                        // If clicking row but not checkbox, open drawer
                        if (e.target.type !== "checkbox") setSelected(a)
                      }}
                      onKeyDown={(ev) => {
                        if (ev.key === "Enter") setSelected(a)
                      }}
                      tabIndex={0}
                    >
                      <td onClick={(e) => e.stopPropagation()} style={{ paddingTop: "0.75rem" }}>
                        <input
                          type="checkbox"
                          checked={selectedKeys.has(a.key)}
                          onChange={() => toggleSelect(a.key)}
                          style={{ cursor: "pointer" }}
                        />
                      </td>
                      <td style={{ paddingTop: "0.75rem" }}>
                        <span className="pill" style={{ fontWeight: 900 }}>
                          {a.count}
                        </span>
                      </td>
                      <td className="subtle" style={{ fontSize: "0.85rem", paddingTop: "0.75rem" }}>{a.namespace}</td>
                      <td style={{ fontWeight: 900, paddingTop: "0.75rem" }}>{a.workload}</td>
                      <td style={{ paddingTop: "0.75rem" }}>
                        <span className="mono" style={{ color: "var(--accent)", fontWeight: 800 }}>{a.syscall}</span>
                      </td>
                      <td className="mono" style={{ fontSize: "0.85rem", paddingTop: "0.75rem" }}>{a.comm}</td>
                      <td
                        className="dim"
                        style={{
                          fontSize: "0.85rem",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          maxWidth: 400,
                          paddingTop: "0.75rem"
                        }}
                      >
                        {a.argument}
                      </td>
                      <td style={{ paddingTop: "0.75rem" }}>
                        <Pill tone={actionTone(a.action)}>
                          {a.action === "dry-run-blocked" ? "observed" : a.action}
                        </Pill>
                      </td>
                      <td className="dim" style={{ fontSize: "0.85rem", paddingTop: "0.75rem" }}>{new Date(a.lastSeen).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )
      ) : rows.length === 0 ? (
        <EmptyState title="No events" description="Try widening filters (Action, Namespace, Workload)." />
      ) : (
        <Card className="anim-filter-flash" key={filterKey}>
          <div style={{ overflow: "hidden", borderRadius: "var(--r-lg)" }}>
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 100 }}>Time</th>
                  <th style={{ width: 140 }}>Namespace</th>
                  <th style={{ width: 180 }}>Workload</th>
                  <th style={{ width: 120 }}>Syscall</th>
                  <th style={{ width: 120 }}>Process</th>
                  <th>Argument</th>
                  <th style={{ width: 120 }}>Action</th>
                </tr>
              </thead>
              <tbody key={filterKey}>
                {rows.map((e) => (
                  <tr
                    key={e.id}
                    className="stagger-in"
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelected(e)}
                    onKeyDown={(ev) => {
                      if (ev.key === "Enter") setSelected(e)
                    }}
                    tabIndex={0}
                  >
                    <td className="dim" style={{ fontSize: "0.85rem" }}>{formatTime(e.timestamp)}</td>
                    <td className="subtle" style={{ fontSize: "0.85rem" }}>{e.namespace}</td>
                    <td style={{ fontWeight: 900 }}>{e.workload}</td>
                    <td>
                      <span className="mono" style={{ color: "var(--accent)", fontWeight: 800 }}>
                        {e.syscall}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: "0.85rem" }}>{e.comm}</td>
                    <td style={{ maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: "0.85rem" }} className="dim">
                      {e.isPrefix && (
                        <Folder
                          size={14}
                          style={{
                            display: "inline-block",
                            verticalAlign: "middle",
                            marginRight: "6px",
                            color: "var(--accent)",
                          }}
                        />
                      )}
                      <span style={e.isPrefix ? { fontWeight: 800, color: "var(--accent)" } : {}}>
                        {e.argument}{e.isPrefix ? "*" : ""}
                      </span>
                    </td>
                    <td>
                      <Pill tone={actionTone(e.action)}>
                        {e.action === "dry-run-blocked" ? "observed" : e.action}
                      </Pill>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Pagination Footer */}
      {(mode === "live" || mode === "alerts") && (
        <div className="row" style={{ marginTop: "1rem", justifyContent: "space-between", fontSize: "0.85rem", color: "var(--muted)" }}>
          <div>
            Showing <span style={{ fontWeight: "bold", color: "var(--fg)" }}>{data.length}</span> of <span style={{ fontWeight: "bold", color: "var(--fg)" }}>{totalCount}</span> events
          </div>
          <div className="row" style={{ gap: "1rem" }}>
            <div className="row" style={{ gap: "0.5rem" }}>
              <span>Show:</span>
              <select
                className="select"
                value={pageSize}
                onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
                style={{ padding: "0.2rem 0.5rem", fontSize: "0.85rem" }}
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={500}>500</option>
              </select>
            </div>
            <div className="row" style={{ gap: "0.5rem" }}>
              <Button small secondary disabled={page === 1} onClick={() => setPage(p => Math.max(1, p - 1))}>Previous</Button>
              <div style={{ padding: "0 0.5rem" }}>Page {page}</div>
              <Button small secondary disabled={page * pageSize >= totalCount} onClick={() => setPage(p => p + 1)}>Next</Button>
            </div>
          </div>
        </div>
      )}

      <Drawer
        open={Boolean(selected)}
        title={
          selected
            ? mode === "alerts"
              ? `${selected.workload} — ${selected.syscall}`
              : `${selected.workload} — ${selected.syscall}`
            : ""
        }
        subtitle={
          selected
            ? mode === "alerts"
              ? `${selected.namespace} • ${selected.comm} • occurrences: ${selected.count}`
              : `${selected.namespace} • ${selected.podName}`
            : ""
        }
        onClose={() => setSelected(null)}
      >
        {selected ? (
          mode === "alerts" ? (
            <div className="stack" style={{ gap: "1rem" }}>
              <div className="row between">
                <Pill tone={actionTone(selected.action)}>{selected.action}</Pill>
              </div>

              <Card>
                <CardInner>
                  <div style={{ fontWeight: 900, marginBottom: "0.5rem" }}>Signature</div>
                  <div className="stack" style={{ gap: "0.6rem" }}>
                    <div className="row between">
                      <span className="subtle">Workload</span>
                      <span style={{ fontWeight: 900 }}>{selected.workload}</span>
                    </div>
                    <div className="row between">
                      <span className="subtle">Namespace</span>
                      <span style={{ fontWeight: 900 }}>{selected.namespace}</span>
                    </div>
                    <div className="row between">
                      <span className="subtle">Syscall</span>
                      <span className="mono" style={{ color: "var(--accent)", fontWeight: 900 }}>
                        {selected.syscall}
                      </span>
                    </div>
                    <div className="row between">
                      <span className="subtle">Process</span>
                      <span className="mono" style={{ fontWeight: 800 }}>
                        {selected.comm}
                      </span>
                    </div>
                    <div>
                      <div className="subtle" style={{ fontSize: "0.78rem" }}>
                        Argument
                      </div>
                      {isGeneralizing ? (
                        <div className="stack" style={{ gap: "0.75rem", marginTop: "0.5rem" }}>
                          <input
                            type="text"
                            className="input-compact mono"
                            value={editedArgument}
                            onChange={(e) => setEditedArgument(e.target.value)}
                            autoFocus
                            style={{
                              padding: "0.75rem",
                              width: "100%",
                              background: "rgba(0,0,0,0.3)",
                              border: "1px solid var(--accent)",
                              color: "var(--accent)"
                            }}
                          />
                          <div className="row" style={{ gap: "1rem" }}>
                            <label className="row" style={{ gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                              <input type="checkbox" checked={forcePrefix} onChange={e => setForcePrefix(e.target.checked)} />
                              Prefix Rule (*)
                            </label>
                            <label className="row" style={{ gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                              <input type="checkbox" checked={cleanupMatched} onChange={e => setCleanupMatched(e.target.checked)} />
                              Cleanup redundant
                            </label>
                          </div>
                        </div>
                      ) : (
                        <div
                          className="mono"
                          style={{
                            marginTop: "0.35rem",
                            padding: "0.75rem",
                            borderRadius: 12,
                            background: "rgba(0,0,0,0.25)",
                            border: "1px solid rgba(255,255,255,0.08)",
                          }}
                        >
                          {selected.argument}
                        </div>
                      )}
                    </div>
                  </div>
                </CardInner>
              </Card>

              <Card>
                <CardInner>
                  <div className="row between" style={{ marginBottom: "0.6rem" }}>
                    <div style={{ fontWeight: 900 }}>SOC actions</div>
                    <span className="pill">
                      <TriangleAlert size={14} /> Grouped alert
                    </span>
                  </div>
                  {!isGeneralizing && (
                    <div className="dim" style={{ fontSize: "0.9rem" }}>
                      Approving will resolve all <strong>{selected.count}</strong> occurrences of this signature.
                      <div style={{ marginTop: "0.25rem", color: "var(--accent)" }}>
                        <Sparkles size={12} style={{ marginRight: "0.25rem", display: "inline-block", verticalAlign: "middle" }} />
                        Tip: You can also select multiple alerts in the table to approve in bulk.
                      </div>
                    </div>
                  )}
                  {isGeneralizing && (
                    <div className="dim" style={{ fontSize: "0.9rem" }}>
                      <span style={{ fontWeight: "bold" }}>Generalize Rule:</span> Use this to create a broader policy.
                      For example, instead of approving reading specific files like <code>/etc/hosts</code>, you can approve <code>/etc/*</code> to allow access to the entire directory.
                    </div>
                  )}

                  <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap", marginTop: "0.9rem" }}>
                    {isGeneralizing ? (
                      <>
                        <Button
                          variant="primary"
                          onClick={handleGeneralize}
                          disabled={approving}
                          style={{ flex: 1 }}
                        >
                          {approving ? "Generalizing..." : "Authorize Pattern & Clean"}
                        </Button>
                        <Button onClick={() => setIsGeneralizing(false)} disabled={approving}>
                          Cancel
                        </Button>
                      </>
                    ) : (
                      <>
                        <Button
                          variant="primary"
                          onClick={handleApprove}
                          disabled={approving}
                        >
                          {approving ? "Approving..." : "Approve & learn"}
                        </Button>
                        <Button onClick={() => setIsGeneralizing(true)}>
                          <Brain size={16} /> Generalize Rule
                        </Button>
                        <Button variant="danger">Escalate</Button>
                      </>
                    )}
                  </div>
                </CardInner>
              </Card>

              <Card>
                <CardInner>
                  <div style={{ fontWeight: 900, marginBottom: "0.5rem" }}>Recent occurrences (sample)</div>
                  <div className="dim" style={{ fontSize: "0.9rem" }}>
                    Showing up to 10 most recent occurrences for this signature.
                  </div>

                  <div style={{ marginTop: "0.75rem", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, overflow: "hidden" }}>
                    <table className="table" style={{ fontSize: "0.85rem" }}>
                      <thead>
                        <tr>
                          <th style={{ width: 120 }}>Time</th>
                          <th>Pod</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selected.events.slice(0, 10).map((e) => (
                          <tr key={e.id}>
                            <td className="dim">{new Date(e.timestamp).toLocaleTimeString()}</td>
                            <td className="mono">{e.podName}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardInner>
              </Card>
            </div>
          ) : (
            <div className="stack" style={{ gap: "1rem" }}>
              <div className="row between">
                <Pill tone={actionTone(selected.action)}>{selected.action}</Pill>
              </div>

              <Card>
                <CardInner>
                  <div style={{ fontWeight: 900, marginBottom: "0.5rem" }}>Context</div>
                  <div className="stack" style={{ gap: "0.6rem" }}>
                    <div className="row between">
                      <span className="subtle">Time</span>
                      <span style={{ fontWeight: 800 }}>{new Date(selected.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="row between">
                      <span className="subtle">Process (comm)</span>
                      <span className="mono" style={{ fontWeight: 800 }}>
                        {selected.comm}
                      </span>
                    </div>
                    <div>
                      <div className="subtle" style={{ fontSize: "0.78rem" }}>
                        Argument
                      </div>
                      {isGeneralizing ? (
                        <div className="stack" style={{ gap: "0.75rem", marginTop: "0.5rem" }}>
                          <input
                            type="text"
                            className="input-compact mono"
                            value={editedArgument}
                            onChange={(e) => setEditedArgument(e.target.value)}
                            autoFocus
                            style={{
                              padding: "0.75rem",
                              width: "100%",
                              background: "rgba(0,0,0,0.3)",
                              border: "1px solid var(--accent)",
                              color: "var(--accent)"
                            }}
                          />
                          <div className="row" style={{ gap: "1rem" }}>
                            <label className="row" style={{ gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                              <input type="checkbox" checked={forcePrefix} onChange={e => setForcePrefix(e.target.checked)} />
                              Prefix Rule (*)
                            </label>
                            <label className="row" style={{ gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                              <input type="checkbox" checked={cleanupMatched} onChange={e => setCleanupMatched(e.target.checked)} />
                              Cleanup redundant
                            </label>
                          </div>
                        </div>
                      ) : (
                        <div
                          className="mono"
                          style={{
                            marginTop: "0.35rem",
                            padding: "0.75rem",
                            borderRadius: 12,
                            background: "rgba(0,0,0,0.25)",
                            border: "1px solid rgba(255,255,255,0.08)",
                          }}
                        >
                          {selected.argument}
                        </div>
                      )}
                    </div>
                  </div>
                </CardInner>
              </Card>

              <Card>
                <CardInner>
                  <div className="row between" style={{ marginBottom: "0.6rem" }}>
                    <div style={{ fontWeight: 900 }}>Triage</div>
                    <span className="pill">
                      <TriangleAlert size={14} /> Single event
                    </span>
                  </div>
                  {!isGeneralizing && (
                    <div className="dim" style={{ fontSize: "0.9rem" }}>
                      In practice, teams usually triage from the grouped inbox above.
                    </div>
                  )}

                  <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap", marginTop: "0.9rem" }}>
                    {isGeneralizing ? (
                      <>
                        <Button
                          variant="primary"
                          onClick={handleGeneralize}
                          disabled={approving}
                          style={{ flex: 1 }}
                        >
                          {approving ? "Generalizing..." : "Authorize Pattern & Clean"}
                        </Button>
                        <Button onClick={() => setIsGeneralizing(false)} disabled={approving}>
                          Cancel
                        </Button>
                      </>
                    ) : (
                      <>
                        <Button
                          variant="primary"
                          onClick={handleApprove}
                          disabled={approving}
                        >
                          {approving ? "Approving..." : "Approve & learn"}
                        </Button>
                        <Button onClick={() => setIsGeneralizing(true)}>
                          <Brain size={16} /> Generalize Rule
                        </Button>
                        <Button variant="danger">Block</Button>
                      </>
                    )}
                  </div>
                </CardInner>
              </Card>
            </div>
          )
        ) : null}
      </Drawer>

      {selectedKeys.size > 0 && (
        <div className="bulk-bar">
          <div className="row" style={{ gap: "1rem" }}>
            <span style={{ fontWeight: 950, color: "var(--accent)", fontSize: "1.1rem" }}>
              {selectedKeys.size} signatures selected
            </span>
            <span className="subtle">|</span>
            <span className="dim" style={{ fontSize: "0.9rem", fontWeight: 600 }}>
              Audit and add to baseline
            </span>
          </div>
          <div className="row" style={{ gap: "0.75rem" }}>
            <Button
              variant="primary"
              onClick={handleBulkApprove}
              disabled={approving}
              style={{ padding: "0.6rem 1.2rem", fontWeight: 800 }}
            >
              {approving ? "Authorizing..." : "Authorize All"}
            </Button>
            <Button onClick={() => setSelectedKeys(new Set())} style={{ padding: "0.6rem 1rem" }}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
