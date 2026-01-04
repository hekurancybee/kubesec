import clsx from "clsx"

export function Tabs({ value, onValueChange, items }) {
  return (
    <div
      className="tabs"
      role="tablist"
      aria-label="Tabs"
      style={{ display: "inline-flex", gap: 6, padding: 6, borderRadius: 14 }}
    >
      {items.map((it) => (
        <button
          key={it.value}
          type="button"
          role="tab"
          aria-selected={value === it.value}
          className={clsx("tab", value === it.value && "tab-active")}
          onClick={() => onValueChange(it.value)}
        >
          {it.icon ? <span style={{ display: "inline-flex" }}>{it.icon}</span> : null}
          {it.label}
          {typeof it.badge === "number" ? <span className="pill">{it.badge}</span> : null}
        </button>
      ))}
    </div>
  )
}
