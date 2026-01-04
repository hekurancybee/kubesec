import { clamp } from "../../lib/format"

export function Progress({ value = 0 }) {
  const v = clamp(Number(value) || 0, 0, 100)
  return (
    <div style={{ width: "100%" }}>
      <div
        style={{
          width: "100%",
          height: 8,
          borderRadius: 999,
          background: "rgba(255,255,255,0.06)",
          border: "1px solid rgba(255,255,255,0.06)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${v}%`,
            height: "100%",
            borderRadius: 999,
            background: "linear-gradient(90deg, rgba(183,255,42,0.85), rgba(90,167,255,0.7))",
          }}
        />
      </div>
    </div>
  )
}
