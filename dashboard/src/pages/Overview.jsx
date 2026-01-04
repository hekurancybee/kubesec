import { useEffect, useMemo, useState } from "react"
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import {
  Activity,
  Brain,
  CheckCircle2,
  FileUp,
  Shield,
  Sparkles,
  Terminal,
  TriangleAlert,
} from "lucide-react"
import { Card, CardInner } from "../components/ui/Card"
import { Pill } from "../components/ui/Pill"
import { Button } from "../components/ui/Button"
import { Drawer } from "../components/ui/Drawer"
import { CommandPalette } from "../components/ui/CommandPalette"
import { useToast } from "../components/ui/Toast"
import { DetectionsPanel } from "../components/DetectionsPanel"
import { fetchStatsSummary, fetchTimeseries, fetchTopNamespaces } from "../lib/api"
import { mockEvents, mockTimeseries } from "../mockData"

export default function Overview() {
  const toast = useToast()
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [drawer, setDrawer] = useState(null)

  const [summary, setSummary] = useState({ totalEvents: 0, blockedEvents: 0, observedEvents: 0, learnedEvents: 0 })
  const [timeseries, setTimeseries] = useState([])
  const [topNamespaces, setTopNamespaces] = useState([])
  const [loading, setLoading] = useState(true)
  const [windowMinutes, setWindowMinutes] = useState(15) // Default to 15m for high-density overview

  const windows = [
    { label: "15m", value: 15 },
    { label: "1h", value: 60 },
    { label: "4h", value: 240 },
    { label: "24h", value: 1440 },
    { label: "7d", value: 10080 },
  ]

  useEffect(() => {
    async function load() {
      try {
        const [s, t, n] = await Promise.all([
          fetchStatsSummary(windowMinutes),
          fetchTimeseries(windowMinutes),
          fetchTopNamespaces(windowMinutes),
        ])
        setSummary(s)
        setTimeseries(t)
        setTopNamespaces(n)
      } catch (err) {
        console.error("Failed to fetch overview data:", err)
      } finally {
        setLoading(false)
      }
    }

    load()
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [windowMinutes])

  // (Control plane) keep KPIs minimal on Overview; details live in Workloads / Detections / Learning.
  // Counts remain available via other views.



  const commands = useMemo(() => {
    return [
      {
        id: "policy-enforce-on",
        group: "Policy",
        label: "Enable enforcement (global)",
        description: "Switch cluster-wide enforcement to Active.",
        keywords: ["enforce", "enable", "policy"],
      },
      {
        id: "policy-enforce-off",
        group: "Policy",
        label: "Emergency disable enforcement",
        description: "Disable enforcement globally (break glass).",
        keywords: ["disable", "break glass", "policy"],
      },
      {
        id: "policy-deploy",
        group: "Policy",
        label: "Deploy policy bundle",
        description: "Apply latest learned syscall profiles.",
        keywords: ["deploy", "policy", "bundle"],
      },
      {
        id: "learning-push",
        group: "Learning",
        label: "Sync policy baseline",
        description: "Verify and sync auto-learned baselines cluster-wide.",
        keywords: ["learning", "baseline", "policy", "sync"],
      },
      {
        id: "learning-start",
        group: "Learning",
        label: "Start training (baseline)",
        description: "Begin collecting normal syscall baselines.",
        keywords: ["train", "baseline", "start"],
      },
      {
        id: "cluster-apply",
        group: "Cluster",
        label: "Apply manifest",
        description: "Apply YAML to the cluster (mock).",
        keywords: ["kubectl", "apply", "manifest", "yaml"],
      },
      {
        id: "cluster-cordon",
        group: "Cluster",
        label: "Cordon selected nodes",
        description: "Prevent new pods from scheduling to selected nodes.",
        keywords: ["cordon", "node", "scheduling"],
      },
      {
        id: "cluster-rollout",
        group: "Cluster",
        label: "Restart rollout (deployment)",
        description: "Trigger a rolling restart (mock).",
        keywords: ["rollout", "restart", "deployment"],
      },
      {
        id: "response-isolate",
        group: "Response",
        label: "Isolate workload",
        description: "Quarantine network/permissions for a workload.",
        keywords: ["isolate", "quarantine", "response"],
      },
      {
        id: "export-evidence",
        group: "Response",
        label: "Export evidence bundle",
        description: "Download logs + policy + syscall traces.",
        keywords: ["export", "evidence", "download"],
      },
    ]
  }, [])

  function runCommand(cmd) {
    if (cmd?.type === "__open__") {
      setPaletteOpen(true)
      return
    }

    const title = cmd?.label ?? "Command"
    toast.push({
      title,
      description: "Mock executed — will be wired to backend later.",
      tone: cmd?.group === "Response" ? "warn" : cmd?.id?.includes("off") ? "bad" : "good",
    })
  }
  return (
    <div className="stack" style={{ gap: "1rem" }}>
      <div className="row between" style={{ gap: "1rem", flexWrap: "wrap" }}>
        <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
          <span className={`pill ${summary.hasLearning ? "pill-warn" : "pill-accent"}`}>
            {summary.hasLearning ? <Brain size={14} /> : <Sparkles size={14} />}
            Baseline: {summary.hasLearning ? "Learning" : "Stable"}
          </span>
          <div className="row" style={{ gap: "0.25rem", background: "rgba(255,255,255,0.03)", padding: "2px", borderRadius: "80px", border: "1px solid rgba(255,255,255,0.06)" }}>
            {windows.map(w => (
              <button
                key={w.value}
                onClick={() => setWindowMinutes(w.value)}
                className={`pill-btn ${windowMinutes === w.value ? 'active' : ''}`}
                style={{
                  fontSize: '0.7rem',
                  padding: '4px 10px',
                  border: 'none',
                  background: windowMinutes === w.value ? 'rgba(255,255,255,0.1)' : 'transparent',
                  color: windowMinutes === w.value ? '#fff' : 'rgba(255,255,255,0.4)',
                  cursor: 'pointer',
                  borderRadius: '60px',
                  fontWeight: windowMinutes === w.value ? 700 : 400,
                  transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)'
                }}
              >
                {w.label}
              </button>
            ))}
          </div>
        </div>

        <div className="row" style={{ gap: "0.5rem" }}>
          <Button onClick={() => setPaletteOpen(true)}>
            <Terminal size={16} /> All Commands
          </Button>
          <Button variant="primary" onClick={() => runCommand(commands.find((c) => c.id === "policy-deploy"))}>
            <CheckCircle2 size={16} /> Deploy
          </Button>
        </div>
      </div>

      <div className="row" style={{ gap: "1rem", flexWrap: "wrap", marginBottom: "0.5rem" }}>
        <Card style={{ flex: "1 1 200px" }}>
          <CardInner>
            <div className="row" style={{ gap: "0.6rem", marginBottom: "0.5rem" }}>
              <Activity size={16} className="subtle" />
              <div className="subtle" style={{ fontSize: "0.8rem" }}>Total events ({windows.find(w => w.value === windowMinutes)?.label || '15m'})</div>
            </div>
            <div style={{ fontSize: "1.75rem", fontWeight: 950 }}>{(summary.totalEvents || 0).toLocaleString()}</div>
          </CardInner>
        </Card>
        <Card style={{ flex: "1 1 200px" }}>
          <CardInner>
            <div className="row" style={{ gap: "0.6rem", marginBottom: "0.5rem" }}>
              <Brain size={16} style={{ color: "var(--accent)" }} />
              <div className="subtle" style={{ fontSize: "0.8rem" }}>Syscalls learned</div>
            </div>
            <div style={{ fontSize: "1.75rem", fontWeight: 950, color: "var(--accent)" }}>{(summary.learnedEvents || 0).toLocaleString()}</div>
          </CardInner>
        </Card>
        <Card style={{ flex: "1 1 200px" }}>
          <CardInner>
            <div className="row" style={{ gap: "0.6rem", marginBottom: "0.5rem" }}>
              <Shield size={16} style={{ color: "var(--yellow)" }} />
              <div className="subtle" style={{ fontSize: "0.8rem" }}>Observed (Dry-Run)</div>
            </div>
            <div style={{ fontSize: "1.75rem", fontWeight: 950, color: "var(--yellow)" }}>{(summary.observedEvents || 0).toLocaleString()}</div>
          </CardInner>
        </Card>
        <Card style={{ flex: "1 1 200px" }}>
          <CardInner>
            <div className="row" style={{ gap: "0.6rem", marginBottom: "0.5rem" }}>
              <TriangleAlert size={16} style={{ color: "var(--red)" }} />
              <div className="subtle" style={{ fontSize: "0.8rem" }}>Active blocks</div>
            </div>
            <div style={{ fontSize: "1.75rem", fontWeight: 950, color: "var(--red)" }}>{(summary.blockedEvents || 0).toLocaleString()}</div>
          </CardInner>
        </Card>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(12, minmax(0, 1fr))",
          gap: "1rem",
          alignItems: "start",
        }}
      >
        {/* Charts (fixed-width, Mandiant-style sparklines) */}
        <div style={{ gridColumn: "span 12", display: "flex", gap: "1rem", flexWrap: "wrap" }}>
          <Card style={{ width: 300 }}>
            <CardInner>
              <div className="row between" style={{ marginBottom: "0.45rem" }}>
                <div style={{ fontWeight: 950, fontSize: "0.8rem" }}>Events</div>
                <span className="pill" style={{ fontSize: "0.7rem" }}>Total</span>
              </div>
              <div style={{ width: "100%", height: 50 }}>
                <ResponsiveContainer>
                  <AreaChart data={timeseries.length > 0 ? timeseries : mockTimeseries} margin={{ left: 0, right: 0, top: 6, bottom: 0 }}>
                    <defs>
                      <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#5aa7ff" stopOpacity={0.20} />
                        <stop offset="95%" stopColor="#5aa7ff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <Tooltip
                      contentStyle={{
                        background: "rgba(15,20,35,0.95)",
                        border: "1px solid rgba(255,255,255,0.10)",
                        borderRadius: 12,
                        boxShadow: "var(--shadow-md)",
                        padding: "0.6rem 0.7rem",
                      }}
                      labelStyle={{ color: "rgba(255,255,255,0.8)" }}
                      cursor={{ stroke: "rgba(255,255,255,0.18)", strokeDasharray: "3 3" }}
                    />
                    <XAxis dataKey="t" hide />
                    <YAxis hide />
                    <Area
                      type="monotone"
                      dataKey={(d) => (d.allowed ?? 0) + (d.learned ?? 0) + (d.blocked ?? 0) + (d.observed ?? 0)}
                      name="total"
                      stroke="#5aa7ff"
                      fill="url(#gTotal)"
                      strokeWidth={1.7}
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardInner>
          </Card>

          <Card style={{ width: 300 }}>
            <CardInner>
              <div className="row between" style={{ marginBottom: "0.45rem" }}>
                <div style={{ fontWeight: 950, fontSize: "0.8rem" }}>Activity</div>
                <span className="pill pill-bad" style={{ fontSize: "0.7rem" }}>Violations</span>
              </div>
              <div style={{ width: "100%", height: 50 }}>
                <ResponsiveContainer>
                  <BarChart
                    data={timeseries.length > 0 ? timeseries : mockTimeseries}
                    margin={{ left: 0, right: 0, top: 6, bottom: 0 }}
                    barCategoryGap={2}
                    barGap={0}
                  >
                    <Tooltip
                      contentStyle={{
                        background: "rgba(15,20,35,0.95)",
                        border: "1px solid rgba(255,255,255,0.10)",
                        borderRadius: 12,
                        boxShadow: "var(--shadow-md)",
                        padding: "0.6rem 0.7rem",
                      }}
                      labelStyle={{ color: "rgba(255,255,255,0.8)" }}
                      cursor={{ fill: "rgba(255,255,255,0.05)" }}
                    />
                    <XAxis dataKey="t" hide />
                    <YAxis hide />
                    <Bar
                      dataKey="blocked"
                      stackId="a"
                      fill="#ff3b3b"
                      radius={[0, 0, 0, 0]}
                      barSize={4}
                      isAnimationActive={false}
                    />
                    <Bar
                      dataKey="observed"
                      stackId="a"
                      fill="#ffd43b"
                      radius={[2, 2, 0, 0]}
                      barSize={4}
                      isAnimationActive={false}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardInner>
          </Card>

          <Card style={{ width: 300 }}>
            <CardInner>
              <div className="row between" style={{ marginBottom: "0.45rem" }}>
                <div style={{ fontWeight: 950, fontSize: "0.8rem" }}>Namespaces</div>
                <span className="pill" style={{ fontSize: "0.7rem" }}>Top blocked</span>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {topNamespaces.length === 0 ? (
                  <div className="dim" style={{ fontSize: "0.9rem" }}>
                    No blocked events.
                  </div>
                ) : (
                  topNamespaces.map((n) => {
                    const max = topNamespaces[0]?.blocked ?? 1
                    const pct = Math.max(0.08, n.blocked / max)
                    return (
                      <div key={n.namespace} style={{ display: "grid", gridTemplateColumns: "1fr 90px", gap: 10, alignItems: "center" }}>
                        <div style={{ minWidth: 0 }}>
                          <div className="subtle" style={{ fontSize: "0.78rem", marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {n.namespace}
                          </div>
                          <div style={{ height: 6, borderRadius: 999, border: "1px solid rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.03)", overflow: "hidden" }}>
                            <div style={{ width: `${pct * 100}%`, height: "100%", background: "rgba(255,59,59,0.75)" }} />
                          </div>
                        </div>
                        <div className="mono" style={{ textAlign: "right", color: "rgba(255,255,255,0.75)", fontSize: "0.85rem" }}>
                          {n.blocked}
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </CardInner>
          </Card>
        </div>

        {/* Detections (full table + filters) */}
        <Card style={{ gridColumn: "span 12" }}>
          <CardInner>
            <DetectionsPanel
              title="Detections"
              defaultMode="alerts"
              defaultAction="blocked"
              defaultRisk="all"
              compactHeader
              hideActionFilter={true}
              windowMinutes={windowMinutes}
            />
          </CardInner>
        </Card>
      </div>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        commands={commands}
        onRun={(cmd) => {
          if (cmd?.type === "__open__") setPaletteOpen(true)
          else runCommand(cmd)
        }}
      />

      <Drawer
        open={Boolean(drawer)}
        title={drawer?.title}
        subtitle={drawer?.subtitle}
        onClose={() => setDrawer(null)}
        width={560}
      >
        {drawer?.type === "apply" ? (
          <div className="stack" style={{ gap: "1rem" }}>
            <div className="subtle">Paste YAML (mock):</div>
            <textarea
              className="input"
              rows={10}
              defaultValue={`apiVersion: v1\nkind: Namespace\nmetadata:\n  name: demo`}
              style={{ resize: "vertical" }}
            />
            <div className="row" style={{ gap: "0.5rem", justifyContent: "flex-end" }}>
              <Button onClick={() => setDrawer(null)}>Cancel</Button>
              <Button
                variant="primary"
                onClick={() => {
                  toast.push({ title: "Manifest applied", description: "Mock: kubectl apply -f -", tone: "good" })
                  setDrawer(null)
                }}
              >
                <FileUp size={16} /> Apply
              </Button>
            </div>
          </div>
        ) : drawer?.type === "cordon" ? (
          <div className="stack" style={{ gap: "1rem" }}>
            <div className="dim">Select nodes to cordon (mock):</div>
            <div className="stack" style={{ gap: "0.5rem" }}>
              {["node-01", "node-02", "node-03", "node-04"].map((n) => (
                <label key={n} className="row" style={{ gap: "0.5rem" }}>
                  <input type="checkbox" />
                  <span className="mono">{n}</span>
                </label>
              ))}
            </div>
            <div className="row" style={{ gap: "0.5rem", justifyContent: "flex-end" }}>
              <Button onClick={() => setDrawer(null)}>Cancel</Button>
              <Button
                variant="primary"
                onClick={() => {
                  toast.push({ title: "Nodes cordoned", description: "Mock scheduling protection applied.", tone: "warn" })
                  setDrawer(null)
                }}
              >
                <Shield size={16} /> Cordon
              </Button>
            </div>
          </div>
        ) : drawer?.type === "console" ? (
          <div className="stack" style={{ gap: "1rem" }}>
            <div className="dim">Command console (mock):</div>
            <div className="mono" style={{ padding: "0.8rem", borderRadius: 12, border: "1px solid rgba(255,255,255,0.08)", background: "rgba(0,0,0,0.25)" }}>
              kubectl get pods -A
            </div>
            <div className="row" style={{ gap: "0.5rem", justifyContent: "flex-end" }}>
              <Button onClick={() => setDrawer(null)}>Close</Button>
              <Button
                variant="primary"
                onClick={() => {
                  toast.push({ title: "Command executed", description: "Mock: output streamed.", tone: "neutral" })
                }}
              >
                <Terminal size={16} /> Run
              </Button>
            </div>
          </div>
        ) : drawer?.type === "isolate" ? (
          <div className="stack" style={{ gap: "1rem" }}>
            <div className="dim">Isolate a workload (mock):</div>
            <select className="select" defaultValue="payment-api">
              <option value="payment-api">prod / payment-api</option>
              <option value="nginx-ingress">ingress-nginx / nginx-ingress</option>
              <option value="redis-master">prod / redis-master</option>
            </select>
            <div className="row" style={{ gap: "0.5rem", justifyContent: "flex-end" }}>
              <Button onClick={() => setDrawer(null)}>Cancel</Button>
              <Button
                variant="danger"
                onClick={() => {
                  toast.push({ title: "Workload isolated", description: "Mock: quarantine policy applied.", tone: "bad" })
                  setDrawer(null)
                }}
              >
                <TriangleAlert size={16} /> Isolate
              </Button>
            </div>
          </div>
        ) : drawer?.type === "risk" ? (
          <div className="stack" style={{ gap: "1rem" }}>
            <div className="row between">
              <span className="pill pill-bad">blocked</span>
              <span className="pill">risk: {drawer?.event?.risk}</span>
            </div>
            <div className="mono" style={{ padding: "0.8rem", borderRadius: 12, border: "1px solid rgba(255,255,255,0.08)", background: "rgba(0,0,0,0.25)" }}>
              {drawer?.event?.argument}
            </div>
            <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
              <Button variant="primary" onClick={() => toast.push({ title: "Approved & learned", description: "Mock: signature added to learning.", tone: "good" })}>
                <Brain size={16} /> Approve & learn
              </Button>
              <Button onClick={() => toast.push({ title: "Suppress", description: "Mock: muted signature.", tone: "neutral" })}>
                <Sparkles size={16} /> Suppress
              </Button>
              <Button variant="danger" onClick={() => toast.push({ title: "Escalated", description: "Mock: incident created.", tone: "bad" })}>
                <TriangleAlert size={16} /> Escalate
              </Button>
            </div>
          </div>
        ) : null}
      </Drawer>
    </div >
  )
}
