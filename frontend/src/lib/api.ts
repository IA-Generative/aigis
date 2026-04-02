export const DEVICE_SERVICE_BASE_URL = window.__ENV?.VITE_API_URL ?? import.meta.env.VITE_API_URL ?? 'http://localhost:8080/api'

export async function apiFetch(url, options: RequestInit = {}) {
  const response = await fetch(url, options)
  if (!response.ok) {
    let body = ''
    try { body = await response.text() } catch (_) {}
    throw new Error(`${response.status} ${response.statusText}${body ? ` — ${body}` : ''}`)
  }
  const ct = response.headers.get('content-type') || ''
  if (ct.includes('application/json')) return response.json()
  return response.text()
}

// ── JWT helpers ────────────────────────────────────────────────────────────────
export function decodeJWT(token) {
  const parts = token.split('.')
  if (parts.length < 2) throw new Error('JWT invalide')
  const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
  const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4)
  return JSON.parse(atob(padded))
}

export function isTokenExpired(token) {
  try {
    const decoded = decodeJWT(token)
    if (!decoded.exp) return true
    return decoded.exp <= Math.floor(Date.now() / 1000) + 10
  } catch (_) {
    return true
  }
}
