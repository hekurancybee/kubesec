import clsx from "clsx"

export function Button({
  variant = "default",
  size = "md",
  className,
  children,
  ...props
}) {
  const classes = clsx(
    "btn",
    variant === "primary" && "btn-primary",
    variant === "danger" && "btn-danger",
    size === "sm" && "btn-sm",
    className,
  )

  return (
    <button className={classes} {...props}>
      {children}
    </button>
  )
}

export function IconButton({ className, children, ...props }) {
  return (
    <button className={clsx("btn icon-btn", className)} {...props}>
      {children}
    </button>
  )
}
