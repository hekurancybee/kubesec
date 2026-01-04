import { useEffect, useMemo, useState } from "react"
import {
    Brain,
    Check,
    ShieldBan,
    Sparkles,
    Search,
    Trash2,
    ChevronRight,
    Network,
    FileCode,
    Cpu,
    LayoutGrid,
    MoreVertical,
    RefreshCw,
    Eraser,
    Zap,
    Download,
    History,
    FileText,
    ShieldAlert,
    ChevronDown
} from "lucide-react"
import { Card, CardInner } from "../components/ui/Card"
import { Pill } from "../components/ui/Pill"
import { Button } from "../components/ui/Button"
import { Drawer } from "../components/ui/Drawer"
import { EmptyState } from "../components/ui/EmptyState"
import { useToast } from "../components/ui/Toast"
import { formatDateTime } from "../lib/format"
import {
    fetchWorkloads,
    fetchPolicyBaseline,
    approveSyscall,
    revokeSyscall,
    clearBaseline,
    setWorkloadMode,
    fetchPolicyAudit,
    fetchWorkloadBaseline
} from "../lib/api"
import { mockPolicyBaseline } from "../mockData"

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

function syscallIcon(name) {
    if (name.includes("open") || name.includes("read") || name.includes("write")) return <FileCode size={16} />
    if (name.includes("socket") || name.includes("connect") || name.includes("send")) return <Network size={16} />
    return <Cpu size={16} />
}

export default function PolicyAudit() {
    const [workloads, setWorkloads] = useState([])
    const [data, setData] = useState([])
    const [loading, setLoading] = useState(true)
    const [policiesLoading, setPoliciesLoading] = useState(false)
    const [revoking, setRevoking] = useState(false)
    const [selected, setSelected] = useState(null)
    const [selectedIds, setSelectedIds] = useState(new Set())

    // UI State for drill-down
    const [selectedNamespace, setSelectedNamespace] = useState(null)
    const [selectedWorkload, setSelectedWorkload] = useState(null)

    // Filters & Pagination
    const [search, setSearch] = useState("")
    const [riskFilter, setRiskFilter] = useState("all")
    const [categoryFilter, setCategoryFilter] = useState("all")
    const [page, setPage] = useState(1)
    const pageSize = 25

    const [auditHistory, setAuditHistory] = useState([])
    const [auditLoading, setAuditLoading] = useState(false)
    const [exportLoading, setExportLoading] = useState(false)
    const [showExport, setShowExport] = useState(false)
    const [drawerTab, setDrawerTab] = useState("overview") // overview | audit
    const [isGeneralizing, setIsGeneralizing] = useState(false)
    const [editedArgument, setEditedArgument] = useState("")
    const [cleanupMatched, setCleanupMatched] = useState(true)
    const [forcePrefix, setForcePrefix] = useState(true)
    const [approving, setApproving] = useState(false)

    const toast = useToast()

    // 1. Initial Load: Fetch all workloads
    useEffect(() => {
        async function load() {
            try {
                setLoading(true)
                const res = await fetchWorkloads()
                setWorkloads(res)

                // Auto-select first namespace if none selected
                if (res.length > 0 && !selectedNamespace) {
                    const nsList = Array.from(new Set(res.map(w => w.namespace))).sort()
                    setSelectedNamespace(nsList[0])
                }
            } catch (err) {
                console.error("Failed to fetch workloads:", err)
            } finally {
                setLoading(false)
            }
        }
        load()
    }, [])


    // 2. Fetch Policies when workload selection changes
    useEffect(() => {
        if (!selectedWorkload) {
            setData([])
            return
        }

        async function loadPolicies() {
            try {
                setPoliciesLoading(true)
                const policies = await fetchWorkloadBaseline(selectedWorkload.id)
                setData(policies.map(d => ({
                    ...d,
                    workloadKey: d.workload_key,
                    syscallName: d.syscall_name,
                    isPrefix: d.is_prefix,
                    timestamp: d.last_seen,
                    workload: d.workload_key,
                    syscall: d.syscall_name,
                    family: d.syscall_name?.includes("socket") || d.syscall_name?.includes("connect") ? "network" :
                        d.syscall_name?.includes("open") || d.syscall_name?.includes("read") ? "file" : "process"
                })))
                setPage(1)
            } catch (err) {
                console.error("Failed to fetch policies:", err)
                setData(mockPolicyBaseline.filter(p => p.workloadKey === selectedWorkload.id))
            } finally {
                setPoliciesLoading(false)
            }
        }
        loadPolicies()
    }, [selectedWorkload])

    // Derived State: Namespaces
    const namespaces = useMemo(() => {
        return Array.from(new Set(workloads.map(w => w.namespace))).sort()
    }, [workloads])

    // Derived State: Workloads in selected namespace
    const filteredWorkloads = useMemo(() => {
        if (!selectedNamespace) return []
        return workloads.filter(w => w.namespace === selectedNamespace).sort((a, b) => a.name.localeCompare(b.name))
    }, [workloads, selectedNamespace])

    // Master Class Aggregation for the policy table
    const aggregated = useMemo(() => {
        const groups = {}
        data.forEach(item => {
            const key = `${item.workloadKey}:${item.syscallName}:${item.argument}`
            if (!groups[key]) {
                groups[key] = {
                    ...item,
                    id: key, // Use key as stable ID for selection
                    instances: 1,
                    namespaces: new Set([item.namespace]),
                    lastSeen: item.timestamp,
                }
            } else {
                groups[key].instances++
                groups[key].namespaces.add(item.namespace)
                if (new Date(item.timestamp) > new Date(groups[key].lastSeen)) {
                    groups[key].lastSeen = item.timestamp
                }
            }
        })

        return Object.values(groups).filter(item => {
            const matchesSearch = !search ||
                item.syscall.toLowerCase().includes(search.toLowerCase()) ||
                item.argument.toLowerCase().includes(search.toLowerCase())
            const matchesRisk = riskFilter === "all" || item.risk === riskFilter
            const matchesCategory = categoryFilter === "all" || getCategory(item.syscall) === categoryFilter
            return matchesSearch && matchesRisk && matchesCategory
        })
    }, [data, search, riskFilter, categoryFilter])

    const totalPages = Math.ceil(aggregated.length / pageSize)
    const paginated = useMemo(() => {
        const start = (page - 1) * pageSize
        return aggregated.slice(start, start + pageSize)
    }, [aggregated, page])

    // Actions
    async function handleRevoke(item) {
        try {
            await revokeSyscall(item.workloadKey, item.syscallName, item.argument, item.isPrefix)
            toast.push({ title: "Policy Revoked", tone: "warn" })
            setData(prev => prev.filter(x => !(x.workloadKey === item.workloadKey && x.syscallName === item.syscallName && x.argument === item.argument)))
            setSelected(null)
        } catch (err) {
            toast.push({ title: "Revocation Failed", description: err.message, tone: "bad" })
        }
    }

    async function handleBulkRevoke() {
        const toRevoke = aggregated.filter(item => selectedIds.has(item.id))
        setRevoking(true)
        try {
            for (const item of toRevoke) {
                await revokeSyscall(item.workloadKey, item.syscallName, item.argument, item.isPrefix)
            }
            toast.push({ title: `${toRevoke.length} Policies Revoked`, tone: "warn" })
            const revokedKeys = new Set(toRevoke.map(i => `${i.workloadKey}:${i.syscallName}:${i.argument}`))
            setData(prev => prev.filter(x => !revokedKeys.has(`${x.workloadKey}:${x.syscallName}:${x.argument}`)))
            setSelectedIds(new Set())
        } catch (err) {
            toast.push({ title: "Bulk Revocation Failed", description: err.message, tone: "bad" })
        } finally {
            setRevoking(false)
        }
    }

    async function handleGeneralize() {
        if (!selected) return
        setApproving(true)
        try {
            await approveSyscall(
                selected.workloadKey,
                selected.syscallName,
                editedArgument,
                forcePrefix,
                cleanupMatched
            )
            toast.push({
                title: "Pattern Generalized",
                description: `Created ${forcePrefix ? 'prefix' : 'exact'} rule and cleaned up redundant entries.`,
                tone: "good",
            })
            // Refresh data
            const policies = await fetchWorkloadBaseline(selectedWorkload.id)
            setData(policies.map(d => ({
                ...d,
                workloadKey: d.workload_key,
                syscallName: d.syscall_name,
                isPrefix: d.is_prefix,
                timestamp: d.last_seen,
                workload: d.workload_key,
                syscall: d.syscall_name,
                family: d.syscall_name?.includes("socket") || d.syscall_name?.includes("connect") ? "network" :
                    d.syscall_name?.includes("open") || d.syscall_name?.includes("read") ? "file" : "process"
            })))

            setSelected(null)
            setIsGeneralizing(false)
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

    async function handleClearAll() {
        if (!selectedWorkload) return
        if (!confirm(`Are you sure you want to clear the entire baseline for ${selectedWorkload.name}? This will cause all behavior to be audited/blocked immediately.`)) return

        try {
            await clearBaseline(selectedWorkload.id)
            toast.push({ title: "Baseline Cleared", description: `All policies removed for ${selectedWorkload.name}`, tone: "warn" })
            setData([])
        } catch (err) {
            toast.push({ title: "Failed to clear baseline", description: err.message, tone: "bad" })
        }
    }

    async function handleSwitchToTraining() {
        if (!selectedWorkload) return
        try {
            await setWorkloadMode(selectedWorkload.id, "training")
            toast.push({ title: "Switched to Training", description: `${selectedWorkload.name} is now auto-learning behavior.`, tone: "good" })
            await refreshWorkload()
        } catch (err) {
            toast.push({ title: "Failed to switch mode", description: err.message, tone: "bad" })
        }
    }

    async function fetchAuditHistory(workloadKey) {
        try {
            setAuditLoading(true)
            const history = await fetchPolicyAudit(workloadKey)
            setAuditHistory(history)
        } catch (err) {
            console.error("Failed to fetch audit history:", err)
        } finally {
            setAuditLoading(false)
        }
    }

    async function handleExport(format) {
        if (!selectedWorkload) return
        try {
            setExportLoading(true)
            const baseline = await fetchWorkloadBaseline(selectedWorkload.id)

            let content = ""
            let mimeType = ""
            let filename = `kubesec-baseline-${selectedWorkload.name}.${format}`

            if (format === "json") {
                content = JSON.stringify(baseline, null, 2)
                mimeType = "application/json"
            } else if (format === "csv") {
                const headers = "workload,syscall,argument,is_prefix,last_seen\n"
                const rows = baseline.map(item =>
                    `"${item.workload_key}","${item.syscall_name}","${item.argument || ""}",${item.is_prefix},"${item.last_seen}"`
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

            toast.push({ title: "Export Complete", description: `Downloaded ${filename}`, tone: "good" })
        } catch (err) {
            toast.push({ title: "Export Failed", description: err.message, tone: "bad" })
        } finally {
            setExportLoading(false)
        }
    }

    async function handleComplianceReport() {
        if (!selectedWorkload) return
        try {
            setExportLoading(true)
            const baseline = await fetchWorkloadBaseline(selectedWorkload.id)
            const audit = await fetchPolicyAudit(selectedWorkload.id)

            const report = `
# KubeSec Policy Compliance Report
Generated: ${new Date().toLocaleString()}

## Workload Identity
- **Name**: ${selectedWorkload.name}
- **Namespace**: ${selectedWorkload.namespace}
- **Kind**: ${selectedWorkload.kind}
- **Template Hash**: ${selectedWorkload.templateHash}
- **Status**: ${selectedWorkload.status.toUpperCase()}
- **Policy Version**: ${selectedWorkload.policyVersion}

## Executive Summary
This report summarizes the behavioral baseline enforced for the workload.
A total of ${baseline.length} syscall patterns are currently authorized.

## Active Policies
${baseline.map(p => `- ${p.syscall_name}(${p.argument || "*"}) [Last Sync: ${new Date(p.last_seen).toLocaleDateString()}]`).join("\n")}

## Governance & Audit History
${audit.length === 0 ? "No manual changes recorded." : audit.map(a => `- ${new Date(a.timestamp).toLocaleString()}: ${a.action} by ${a.user_id} (Reason: ${a.reason || "None"})`).join("\n")}

---
*Report generated by KubeSec Agent*
`
            const blob = new Blob([report], { type: "text/markdown" })
            const url = URL.createObjectURL(blob)
            const link = document.createElement("a")
            link.href = url
            link.download = `compliance-report-${selectedWorkload.name}.md`
            link.click()
            URL.revokeObjectURL(url)

            toast.push({ title: "Report Generated", description: "Compliance summary downloaded as Markdown.", tone: "good" })
        } catch (err) {
            toast.push({ title: "Reporting Failed", description: err.message, tone: "bad" })
        } finally {
            setExportLoading(false)
        }
    }

    useEffect(() => {
        if (selected) {
            setEditedArgument(selected.argument || "")
            setIsGeneralizing(false)
            setForcePrefix(selected.argument?.includes('/') || selected.isPrefix)
        }
    }, [selected])

    useEffect(() => {
        if (selectedWorkload && drawerTab === "audit") {
            fetchAuditHistory(selectedWorkload.id)
        }
    }, [selectedWorkload, drawerTab])

    async function handlePromoteToEnforcing() {
        if (!selectedWorkload) return
        try {
            await setWorkloadMode(selectedWorkload.id, "enforce")
            toast.push({ title: "Promoted to Enforced", description: `${selectedWorkload.name} is now actively blocking unknown syscalls.`, tone: "good" })
            await refreshWorkload()
        } catch (err) {
            toast.push({ title: "Failed to promote workload", description: err.message, tone: "bad" })
        }
    }

    async function refreshWorkload() {
        const updatedWorkloads = await fetchWorkloads()
        setWorkloads(updatedWorkloads)
        const updated = updatedWorkloads.find(w => w.id === selectedWorkload.id)
        if (updated) setSelectedWorkload(updated)
    }

    const toggleSelect = (id) => {
        const next = new Set(selectedIds)
        if (next.has(id)) next.delete(id)
        else next.add(id)
        setSelectedIds(next)
    }

    if (loading) return <div className="centered" style={{ padding: "4rem" }}><RefreshCw className="anim-spin subtle" /></div>

    return (
        <div className="row items-start" style={{ gap: "1.5rem", height: "100%", overflow: "hidden" }}>
            {/* Sidebar 1: Namespace Selector */}
            <aside className="stack" style={{ width: 220, flex: "0 0 auto" }}>
                <div className="subtle uppercase bold small" style={{ paddingLeft: "0.5rem" }}>Namespace</div>
                <div className="card-inner stack" style={{ gap: "0.25rem", padding: 0 }}>
                    {namespaces.map(ns => (
                        <Button
                            key={ns}
                            variant={selectedNamespace === ns ? "primary" : "ghost"}
                            onClick={() => {
                                setSelectedNamespace(ns)
                                setSelectedWorkload(null)
                            }}
                            style={{ justifyContent: "flex-start", textAlign: "left" }}
                        >
                            {ns}
                        </Button>
                    ))}
                </div>
            </aside>

            {/* Sidebar 2: Workload Selector */}
            <aside className="stack" style={{ width: 240, flex: "0 0 auto", borderLeft: "1px solid var(--border)", paddingLeft: "1.5rem" }}>
                <div className="subtle uppercase bold small">Workload</div>
                <div className="card-inner stack" style={{ gap: "0.25rem", padding: 0, overflowY: "auto", maxHeight: "calc(100vh - 200px)" }}>
                    {filteredWorkloads.map(w => (
                        <Button
                            key={w.id}
                            variant={selectedWorkload?.id === w.id ? "primary" : "ghost"}
                            onClick={() => setSelectedWorkload(w)}
                            style={{
                                justifyContent: "flex-start",
                                textAlign: "left",
                                display: "block",
                                height: "auto",
                                padding: "0.5rem 0.75rem"
                            }}
                        >
                            <div className="truncate">{w.name}</div>
                            <div className="dim x-small" style={{ fontSize: "0.7rem" }}>
                                {w.kind} • {w.status}
                            </div>
                        </Button>
                    ))}
                    {filteredWorkloads.length === 0 && <div className="dim small centered" style={{ padding: "2rem 0" }}>No workloads</div>}
                </div>
            </aside>

            {/* Main Content Area */}
            <div className="stack" style={{ flex: 1, minWidth: 0, gap: "1.5rem" }}>
                {!selectedWorkload ? (
                    <div className="card centered" style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", padding: "4rem" }}>
                        <EmptyState
                            title="Select a Workload"
                            description="Audit and manage security policies for a specific container/workload."
                            icon={Brain}
                        />
                    </div>
                ) : (
                    <>
                        {/* Header & Global Actions */}
                        <div className="row between" style={{ alignItems: "flex-start" }}>
                            <div className="stack" style={{ gap: "0.25rem" }}>
                                <div className="row" style={{ gap: "0.75rem" }}>
                                    <h2 style={{ margin: 0 }}>{selectedWorkload.name}</h2>
                                    <Pill tone={selectedWorkload.status === "learning" ? "info" : selectedWorkload.status === "observing" ? "warn" : "good"}>
                                        {selectedWorkload.status === "learning" ? "Learning Mode" : selectedWorkload.status === "observing" ? "Observing" : "Enforcing"}
                                    </Pill>
                                </div>
                                <div className="dim small">
                                    Managed policies for {selectedWorkload.kind} in {selectedWorkload.namespace}
                                </div>
                            </div>

                            <div className="row" style={{ gap: "0.75rem" }}>
                                {selectedWorkload.status === "learning" ? (
                                    <Button variant="primary" onClick={handlePromoteToEnforcing} disabled={exportLoading}>
                                        <ShieldBan size={16} /> Promote to Enforced
                                    </Button>
                                ) : (
                                    <Button variant="ghost" onClick={handleSwitchToTraining} disabled={exportLoading}>
                                        <Sparkles size={16} /> Switch to Learning
                                    </Button>
                                )}

                                <div style={{ position: "relative", display: "inline-block" }}>
                                    <Button variant="ghost" onClick={() => setShowExport(!showExport)} disabled={exportLoading}>
                                        <Download size={16} /> Export <ChevronDown size={14} />
                                    </Button>
                                    {showExport && (
                                        <>
                                            <div
                                                style={{ position: "fixed", inset: 0, zIndex: 90 }}
                                                onClick={() => setShowExport(false)}
                                            />
                                            <div className="card shadow-lg anim-fade-in" style={{
                                                position: "absolute",
                                                top: "100%",
                                                right: 0,
                                                zIndex: 100,
                                                minWidth: 180,
                                                marginTop: "0.5rem",
                                                padding: "0.5rem",
                                                backgroundColor: "#1a1a1a",
                                                border: "1px solid var(--border)",
                                                boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.5)"
                                            }}>
                                                <div className="stack" style={{ gap: "0.25rem" }}>
                                                    <Button variant="ghost" size="sm" onClick={() => { handleExport("csv"); setShowExport(false); }} style={{ justifyContent: "flex-start" }}>CSV Baseline</Button>
                                                    <Button variant="ghost" size="sm" onClick={() => { handleExport("json"); setShowExport(false); }} style={{ justifyContent: "flex-start" }}>JSON Baseline</Button>
                                                    <hr style={{ margin: "0.25rem 0", borderColor: "var(--border)" }} />
                                                    <Button variant="ghost" size="sm" onClick={() => { handleComplianceReport(); setShowExport(false); }} style={{ justifyContent: "flex-start" }}>
                                                        <FileText size={14} /> Compliance Report (.md)
                                                    </Button>
                                                </div>
                                            </div>
                                        </>
                                    )}
                                </div>

                                <Button variant="danger" onClick={handleClearAll} disabled={exportLoading}>
                                    <Eraser size={16} /> Clear Baseline
                                </Button>
                            </div>
                        </div>

                        {/* Controls: Search, Bulk, Pagination */}
                        <div className="row between">
                            <div className="row relative" style={{ flex: 1, maxWidth: 400 }}>
                                <Search size={18} className="subtle" style={{ position: "absolute", left: "0.75rem" }} />
                                <input
                                    className="input"
                                    placeholder="Search syscalls or arguments..."
                                    value={search}
                                    onChange={e => setSearch(e.target.value)}
                                    style={{ paddingLeft: "2.5rem", width: "100%" }}
                                />
                            </div>

                            <div className="row" style={{ gap: "0.75rem" }}>
                                <select
                                    className="select"
                                    value={riskFilter}
                                    onChange={e => { setRiskFilter(e.target.value); setPage(1); }}
                                    style={{ height: "2.5rem", minWidth: 120 }}
                                >
                                    <option value="all">All Risks</option>
                                    <option value="high">High Risk</option>
                                    <option value="medium">Medium Risk</option>
                                    <option value="low">Low Risk</option>
                                </select>

                                <select
                                    className="select"
                                    value={categoryFilter}
                                    onChange={e => { setCategoryFilter(e.target.value); setPage(1); }}
                                    style={{ height: "2.5rem", minWidth: 140 }}
                                >
                                    <option value="all">All Categories</option>
                                    {Object.keys(CATEGORIES).map(cat => (
                                        <option key={cat} value={cat}>{cat}</option>
                                    ))}
                                    <option value="Other">Other</option>
                                </select>
                            </div>

                            <div className="row" style={{ gap: "1rem" }}>
                                <span className="subtle small">{aggregated.length} policies</span>
                                <div className="row" style={{ gap: "0.5rem" }}>
                                    <Button disabled={page === 1} onClick={() => setPage(page - 1)} variant="ghost" style={{ padding: "0.4rem" }}>Prev</Button>
                                    <span className="dim small">Page {page}/{totalPages || 1}</span>
                                    <Button disabled={page >= totalPages} onClick={() => setPage(page + 1)} variant="ghost" style={{ padding: "0.4rem" }}>Next</Button>
                                </div>
                                {selectedIds.size > 0 && (
                                    <Button variant="danger" onClick={handleBulkRevoke} disabled={revoking}>
                                        <Trash2 size={16} /> {revoking ? "Revoking..." : `Revoke (${selectedIds.size})`}
                                    </Button>
                                )}
                            </div>
                        </div>

                        {/* Policy Table */}
                        <Card style={{ overflow: "visible", flex: 1 }}>
                            <div style={{ overflowX: "auto" }}>
                                <table className="table" style={{ width: "100%", tableLayout: "fixed" }}>
                                    <thead style={{ background: "rgba(0,0,0,0.1)" }}>
                                        <tr>
                                            <th style={{ width: 40, paddingLeft: "1rem" }}><input type="checkbox" onChange={e => {
                                                if (e.target.checked) setSelectedIds(new Set(paginated.map(i => i.id)))
                                                else setSelectedIds(new Set())
                                            }} /></th>
                                            <th style={{ width: 140 }}>Syscall</th>
                                            <th style={{ width: 100 }}>Risk</th>
                                            <th>Argument Pattern</th>
                                            <th style={{ width: 100 }}>Usage</th>
                                            <th style={{ width: 60 }}></th>
                                        </tr>
                                    </thead>
                                    <tbody style={{ verticalAlign: "top" }}>
                                        {policiesLoading ? (
                                            <tr><td colSpan="6" className="centered" style={{ padding: "4rem" }}><RefreshCw className="anim-spin subtle" /></td></tr>
                                        ) : paginated.map(item => (
                                            <tr key={item.id} className="hoverable">
                                                <td style={{ paddingLeft: "1rem", paddingTop: "0.75rem" }}>
                                                    <input
                                                        type="checkbox"
                                                        checked={selectedIds.has(item.id)}
                                                        onChange={() => toggleSelect(item.id)}
                                                    />
                                                </td>
                                                <td style={{ paddingTop: "0.75rem" }}>
                                                    <div className="row" style={{ gap: "0.5rem" }}>
                                                        {syscallIcon(item.syscall)}
                                                        <span className="mono bold">{item.syscall}</span>
                                                    </div>
                                                </td>
                                                <td style={{ paddingTop: "0.75rem" }}>
                                                    <Pill tone={item.risk === "high" ? "bad" : item.risk === "medium" ? "warn" : "neutral"}>
                                                        {item.risk}
                                                    </Pill>
                                                </td>
                                                <td className="mono truncate" style={{ fontSize: "0.85rem", color: "var(--accent)", paddingTop: "0.75rem" }}>
                                                    {item.argument || "*"}
                                                </td>
                                                <td style={{ paddingTop: "0.75rem" }}>
                                                    <Pill tone="good">{item.instances} hits</Pill>
                                                </td>
                                                <td style={{ paddingTop: "0.75rem" }}>
                                                    <div className="row items-start">
                                                        <IconButton onClick={() => {
                                                            setSelected(item)
                                                            setDrawerTab("overview")
                                                        }}>
                                                            <MoreVertical size={16} />
                                                        </IconButton>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            {!policiesLoading && aggregated.length === 0 && (
                                <div style={{ padding: "4rem 1rem" }}>
                                    <EmptyState title="No learned behavior" description="This workload either has no active policies or is currently training." />
                                </div>
                            )}
                        </Card>
                    </>
                )}
            </div>

            {/* Details Drawer */}
            <Drawer
                open={Boolean(selected)}
                title="Policy Governance"
                subtitle={`${selected?.syscall}(${selected?.argument || "*"})`}
                onClose={() => setSelected(null)}
            >
                {selected && (
                    <div className="stack" style={{ gap: "1.5rem" }}>
                        {/* Tabs */}
                        <div className="row" style={{ borderBottom: "1px solid var(--border)", gap: "1.5rem" }}>
                            <button
                                onClick={() => setDrawerTab("overview")}
                                style={{
                                    padding: "0.5rem 0",
                                    borderBottom: drawerTab === "overview" ? "2px solid var(--accent)" : "none",
                                    color: drawerTab === "overview" ? "var(--text)" : "var(--subtle)",
                                    fontWeight: 700,
                                    background: "none",
                                    border: "none",
                                    cursor: "pointer"
                                }}
                            >
                                Overview
                            </button>
                            <button
                                onClick={() => setDrawerTab("audit")}
                                style={{
                                    padding: "0.5rem 0",
                                    borderBottom: drawerTab === "audit" ? "2px solid var(--accent)" : "none",
                                    color: drawerTab === "audit" ? "var(--text)" : "var(--subtle)",
                                    fontWeight: 700,
                                    background: "none",
                                    border: "none",
                                    cursor: "pointer"
                                }}
                            >
                                Audit History
                            </button>
                        </div>

                        {drawerTab === "overview" ? (
                            <div className="stack anim-fade-in" style={{ gap: "1.5rem" }}>
                                <div className="stack" style={{ gap: "0.5rem" }}>
                                    <div className="subtle uppercase bold small">Behavioral Pattern</div>
                                    {isGeneralizing ? (
                                        <div className="stack" style={{ gap: "0.75rem" }}>
                                            <div className="row" style={{ gap: "0.5rem" }}>
                                                <span className="mono bold">{selected.syscall}(</span>
                                                <input
                                                    type="text"
                                                    className="input-compact mono"
                                                    value={editedArgument}
                                                    onChange={(e) => setEditedArgument(e.target.value)}
                                                    autoFocus
                                                    style={{
                                                        flex: 1,
                                                        padding: "0.4rem 0.75rem",
                                                        background: "rgba(0,0,0,0.3)",
                                                        border: "1px solid var(--accent)",
                                                        color: "var(--accent)"
                                                    }}
                                                />
                                                <span className="mono bold">)</span>
                                            </div>
                                            <div className="row" style={{ gap: "1rem" }}>
                                                <label className="row" style={{ gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                                                    <input type="checkbox" checked={forcePrefix} onChange={e => setForcePrefix(e.target.checked)} />
                                                    Prefix (*)
                                                </label>
                                                <label className="row" style={{ gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
                                                    <input type="checkbox" checked={cleanupMatched} onChange={e => setCleanupMatched(e.target.checked)} />
                                                    Cleanup matched
                                                </label>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="card-inner mono" style={{ background: "rgba(0,0,0,0.2)", borderRadius: 8, border: "1px solid var(--border)" }}>
                                            {selected.syscall}({selected.argument || "*"})
                                        </div>
                                    )}
                                    <div className="dim small">
                                        Status: <Pill tone={selected.risk === "high" ? "bad" : "neutral"}>{selected.risk.toUpperCase()} RISK</Pill>
                                    </div>
                                </div>

                                <div className="grid cols-2">
                                    <div className="stack" style={{ gap: "0.25rem" }}>
                                        <div className="dim small">First Learned</div>
                                        <div className="bold">{formatDateTime(selected.timestamp)}</div>
                                    </div>
                                    <div className="stack" style={{ gap: "0.25rem" }}>
                                        <div className="dim small">Instances</div>
                                        <div className="bold">{selected.instances} cluster-wide</div>
                                    </div>
                                </div>

                                <div className="card-inner stack" style={{ gap: "0.5rem", background: "rgba(var(--accent-rgb), 0.05)" }}>
                                    <div className="row" style={{ gap: "0.5rem", color: "var(--accent)" }}>
                                        <ShieldAlert size={16} /> <span className="bold">Compliance Note</span>
                                    </div>
                                    <div className="small dim">
                                        This policy was automatically derived from the workload's behavior hash <span className="mono">{selectedWorkload.templateHash.substring(0, 8)}</span>.
                                    </div>
                                </div>

                                <div className="stack" style={{ gap: "0.75rem", marginTop: "1rem" }}>
                                    {isGeneralizing ? (
                                        <div className="row" style={{ gap: "0.75rem" }}>
                                            <Button
                                                variant="primary"
                                                onClick={handleGeneralize}
                                                disabled={approving}
                                                style={{ flex: 1, height: 48 }}
                                            >
                                                {approving ? "Updating..." : "Authorize Pattern & Clean"}
                                            </Button>
                                            <Button onClick={() => setIsGeneralizing(false)} disabled={approving} style={{ height: 48 }}>
                                                Cancel
                                            </Button>
                                        </div>
                                    ) : (
                                        <>
                                            <Button
                                                variant="primary"
                                                style={{ height: 48 }}
                                                onClick={() => setIsGeneralizing(true)}
                                            >
                                                <Brain size={18} /> Generalize Rule
                                            </Button>
                                            <Button
                                                variant="danger"
                                                style={{ height: 48 }}
                                                onClick={() => handleRevoke(selected)}
                                            >
                                                <Trash2 size={18} /> Revoke Policy
                                            </Button>
                                        </>
                                    )}
                                </div>
                            </div>
                        ) : (
                            <div className="stack anim-fade-in" style={{ gap: "1rem" }}>
                                {auditLoading ? (
                                    <div className="centered" style={{ padding: "2rem" }}><RefreshCw className="anim-spin subtle" /></div>
                                ) : !auditHistory || auditHistory.length === 0 ? (
                                    <div className="dim small centered" style={{ padding: "2rem" }}>No manual audit records found for this workload.</div>
                                ) : (
                                    <div className="stack" style={{ gap: "0.75rem" }}>
                                        {auditHistory.map((item, idx) => (
                                            <div key={idx} className="card-inner stack" style={{ gap: "0.25rem", padding: "0.75rem" }}>
                                                <div className="row between">
                                                    <Pill tone={item.action === "DELETE" ? "bad" : "good"}>{item.action}</Pill>
                                                    <span className="dim x-small">{formatDateTime(item.timestamp)}</span>
                                                </div>
                                                <div className="small">
                                                    <span className="bold">{item.user_id}</span> modified <span className="mono x-small">{item.syscall_name}</span>
                                                </div>
                                                {item.reason && <div className="dim x-small italic text-1" style={{ marginTop: '0.25rem' }}>"{item.reason}"</div>}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}
            </Drawer>
        </div>
    )
}

function IconButton({ children, onClick }) {
    return (
        <button
            className="btn icon-btn"
            onClick={onClick}
            style={{
                background: "transparent",
                border: "none",
                color: "var(--text-3)",
                cursor: "pointer",
                padding: "0.25rem"
            }}
        >
            {children}
        </button>
    )
}
