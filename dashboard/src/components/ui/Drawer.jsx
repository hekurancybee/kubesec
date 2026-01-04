import { useEffect } from "react"
import { X } from "lucide-react"
import { IconButton } from "./Button"

export function Drawer({ open, title, subtitle, onClose, children, width = 520 }) {
  useEffect(() => {
    function onKeyDown(e) {
      if (e.key === "Escape") onClose?.()
    }

    if (open) {
      window.addEventListener("keydown", onKeyDown)
      document.body.style.overflow = "hidden"
    }

    return () => {
      window.removeEventListener("keydown", onKeyDown)
      document.body.style.overflow = ""
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 50,
        background: "rgba(0,0,0,0.55)",
        backdropFilter: "blur(4px)",
        display: "flex",
        justifyContent: "flex-end",
      }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose?.()
      }}
    >
      <div
        className="card"
        style={{
          height: "100%",
          width,
          borderRadius: 0,
          borderLeft: "1px solid rgba(255,255,255,0.10)",
          boxShadow: "var(--shadow-md)",
          overflow: "hidden",
        }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div
          style={{
            padding: "1.25rem 1.25rem 1rem",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: "1rem",
            borderBottom: "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div style={{ fontWeight: 900, fontSize: "1.05rem" }}>{title}</div>
            {subtitle ? (
              <div className="dim" style={{ fontSize: "0.85rem", marginTop: "0.25rem" }}>
                {subtitle}
              </div>
            ) : null}
          </div>
          <IconButton onClick={onClose} aria-label="Close">
            <X size={18} />
          </IconButton>
        </div>
        <div style={{ padding: "1.25rem", overflow: "auto", height: "calc(100% - 64px)" }}>
          {children}
        </div>
      </div>
    </div>
  )
}
