import { useEffect, useMemo, useState } from "react"
import { Search } from "lucide-react"

export function CommandPalette({ open, onClose, commands = [], onRun }) {
  const [query, setQuery] = useState("")

  useEffect(() => {
    function onKeyDown(e) {
      const isCmdK = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k"
      if (!open && isCmdK) {
        e.preventDefault()
        onRun?.({ type: "__open__" })
      }

      if (!open) return

      if (e.key === "Escape") onClose?.()
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [open, onClose, onRun])

  const items = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter((c) => {
      return (
        c.label.toLowerCase().includes(q) ||
        (c.group ?? "").toLowerCase().includes(q) ||
        (c.keywords ?? []).some((k) => k.toLowerCase().includes(q))
      )
    })
  }, [commands, query])

  if (!open) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 80,
        background: "rgba(0,0,0,0.55)",
        backdropFilter: "blur(4px)",
        display: "flex",
        justifyContent: "center",
        alignItems: "flex-start",
        paddingTop: "12vh",
      }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose?.()
      }}
    >
      <div
        className="card"
        style={{
          width: 720,
          maxWidth: "92vw",
          borderRadius: 18,
          overflow: "hidden",
          background: "rgba(15,20,35,0.92)",
          borderColor: "rgba(255,255,255,0.10)",
        }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.65rem",
            padding: "0.9rem 1rem",
            borderBottom: "1px solid rgba(255,255,255,0.10)",
          }}
        >
          <span className="pill" style={{ padding: "0.45rem 0.6rem" }}>
            <Search size={16} />
          </span>
          <input
            className="input"
            autoFocus
            placeholder="Search commands (e.g., 'enforce', 'cordon', 'policy', 'learn')…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <span className="kbd">Esc</span>
        </div>

        <div style={{ maxHeight: "52vh", overflow: "auto" }}>
          {items.length === 0 ? (
            <div style={{ padding: "1rem" }} className="dim">
              No commands match.
            </div>
          ) : (
            <table className="table" style={{ borderBottom: "none" }}>
              <thead>
                <tr>
                  <th>Command</th>
                  <th style={{ width: 200 }}>Group</th>
                  <th style={{ width: 110 }} />
                </tr>
              </thead>
              <tbody>
                {items.map((c) => (
                  <tr
                    key={c.id}
                    style={{ cursor: "pointer" }}
                    onClick={() => {
                      onRun?.(c)
                      onClose?.()
                    }}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        onRun?.(c)
                        onClose?.()
                      }
                    }}
                  >
                    <td>
                      <div style={{ fontWeight: 950 }}>{c.label}</div>
                      {c.description ? (
                        <div className="dim" style={{ fontSize: "0.9rem", marginTop: "0.2rem" }}>
                          {c.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="dim">{c.group}</td>
                    <td style={{ textAlign: "right" }}>
                      <span className="pill">Run</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div
          style={{
            padding: "0.75rem 1rem",
            borderTop: "1px solid rgba(255,255,255,0.10)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "1rem",
          }}
        >
          <div className="dim" style={{ fontSize: "0.9rem" }}>
            Tip: press <span className="kbd">Ctrl</span>+<span className="kbd">K</span> to open.
          </div>
          <div className="row" style={{ gap: "0.5rem" }}>
            <span className="pill">Enter</span>
            <span className="pill">Run</span>
          </div>
        </div>
      </div>
    </div>
  )
}
