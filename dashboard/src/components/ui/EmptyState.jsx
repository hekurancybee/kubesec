import { SearchX } from "lucide-react"
import { Button } from "./Button"

export function EmptyState({
  title = "Nothing to show",
  description = "Try adjusting filters.",
  actionLabel,
  onAction,
}) {
  return (
    <div
      className="card"
      style={{
        padding: "2rem",
        textAlign: "center",
        borderStyle: "dashed",
        borderColor: "rgba(255,255,255,0.14)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "center", marginBottom: "0.75rem" }}>
        <div className="pill" style={{ padding: "0.4rem 0.6rem" }}>
          <SearchX size={16} />
          Empty
        </div>
      </div>
      <div style={{ fontWeight: 800, fontSize: "1.1rem" }}>{title}</div>
      <div className="dim" style={{ marginTop: "0.35rem" }}>
        {description}
      </div>
      {actionLabel && onAction ? (
        <div style={{ marginTop: "1.25rem", display: "flex", justifyContent: "center" }}>
          <Button variant="primary" onClick={onAction}>
            {actionLabel}
          </Button>
        </div>
      ) : null}
    </div>
  )
}
