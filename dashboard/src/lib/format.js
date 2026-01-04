export function formatTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  } catch {
    return String(ts)
  }
}

export function formatDateTime(ts) {
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return String(ts)
  }
}

export function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n))
}
