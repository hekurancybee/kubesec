import clsx from "clsx"

export function Pill({ tone = "neutral", className, children, ...props }) {
  return (
    <span
      className={clsx(
        "pill",
        tone === "accent" && "pill-accent",
        tone === "bad" && "pill-bad",
        tone === "warn" && "pill-warn",
        tone === "good" && "pill-good",
        tone === "info" && "pill-info",
        className,
      )}
      {...props}
    >
      {children}
    </span>
  )
}
