import { useCallback, useMemo, useState } from "react"
import { X } from "lucide-react"
import { IconButton } from "./Button"
import { ToastContext } from "./Toast"

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const dismiss = useCallback((id) => {
    setToasts((t) => t.filter((x) => x.id !== id))
  }, [])

  const push = useCallback(
    (toast) => {
      const id = toast.id ?? `${Date.now()}-${Math.random()}`
      const t = {
        id,
        title: toast.title ?? "Done",
        description: toast.description,
        tone: toast.tone ?? "neutral", // neutral | good | warn | bad
      }
      setToasts((prev) => [t, ...prev].slice(0, 4))
      window.setTimeout(() => dismiss(id), 3200)
      return id
    },
    [dismiss],
  )

  const value = useMemo(() => ({ push, dismiss }), [push, dismiss])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        style={{
          position: "fixed",
          right: 18,
          bottom: 18,
          zIndex: 60,
          display: "flex",
          flexDirection: "column",
          gap: 10,
          width: 340,
        }}
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className="card"
            style={{
              padding: "0.9rem",
              borderRadius: 14,
              background: "rgba(15,20,35,0.92)",
              borderColor:
                t.tone === "bad"
                  ? "rgba(255,59,59,0.45)"
                  : t.tone === "warn"
                    ? "rgba(255,204,51,0.38)"
                    : t.tone === "good"
                      ? "rgba(46,242,161,0.35)"
                      : "rgba(255,255,255,0.10)",
            }}
          >
            <div className="row between" style={{ alignItems: "flex-start" }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 950 }}>{t.title}</div>
                {t.description ? (
                  <div className="dim" style={{ fontSize: "0.9rem", marginTop: "0.25rem" }}>
                    {t.description}
                  </div>
                ) : null}
              </div>
              <IconButton className="icon-btn" onClick={() => dismiss(t.id)} aria-label="Dismiss">
                <X size={16} />
              </IconButton>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
