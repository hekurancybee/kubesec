import clsx from "clsx"

export function Card({ className, children, ...props }) {
  return (
    <div className={clsx("card", className)} {...props}>
      {children}
    </div>
  )
}

export function CardInner({ className, children, ...props }) {
  return (
    <div className={clsx("card-inner", className)} {...props}>
      {children}
    </div>
  )
}
