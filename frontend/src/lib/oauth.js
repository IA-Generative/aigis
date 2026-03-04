/** OAuth 2.0 / PKCE utilities */

const OAUTH_PENDING_KEY = 'device-service:oauth-pending'

function b64Url(bytes) {
  let binary = ''
  bytes.forEach(b => binary += String.fromCharCode(b))
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export function randomString(size = 32) {
  const bytes = new Uint8Array(size)
  crypto.getRandomValues(bytes)
  return b64Url(bytes)
}

export async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return b64Url(new Uint8Array(digest))
}

export function clearOAuthQueryParams() {
  const url = new URL(window.location.href)
  ;['code', 'state', 'session_state', 'iss', 'error', 'error_description', 'error_uri'].forEach(k => url.searchParams.delete(k))
  window.history.replaceState({}, '', url.toString())
}

export function hasOAuthCallbackParams() {
  const params = new URLSearchParams(window.location.search)
  return params.has('code') || params.has('error')
}

export function savePendingOAuth(data) {
  sessionStorage.setItem(OAUTH_PENDING_KEY, JSON.stringify(data))
}

export function loadPendingOAuth() {
  const raw = sessionStorage.getItem(OAUTH_PENDING_KEY)
  return raw ? JSON.parse(raw) : null
}

export function clearPendingOAuth() {
  sessionStorage.removeItem(OAUTH_PENDING_KEY)
}

/**
 * Builds the Keycloak authorization URL and saves pending state.
 * Returns the URL string.
 */
export async function buildAuthUrl(discover, { redirectUri, deviceId = '' } = {}) {
  const state = randomString(24)
  const nonce = randomString(24)
  const codeVerifier = randomString(64)
  const codeChallenge = await sha256Base64Url(codeVerifier)

  savePendingOAuth({ state, nonce, codeVerifier, redirectUri, discover, deviceId })

  const url = new URL(`${discover.auth_base_url}/realms/${encodeURIComponent(discover.realm)}/protocol/openid-connect/auth`)
  url.searchParams.set('client_id', discover.client_id)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('scope', 'openid profile email')
  url.searchParams.set('state', state)
  url.searchParams.set('nonce', nonce)
  url.searchParams.set('code_challenge', codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')
  if (deviceId) url.searchParams.set('device_id', deviceId)

  return url.toString()
}

/**
 * Exchanges the authorization code for tokens.
 * Returns access_token.
 */
export async function exchangeCode(code, state) {
  const pending = loadPendingOAuth()
  if (!pending) throw new Error('OAuth pending state introuvable')
  if (pending.state !== state) throw new Error('OAuth state invalide')

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: pending.discover.client_id,
    code,
    redirect_uri: pending.redirectUri,
    code_verifier: pending.codeVerifier
  })

  const tokenEndpoint = `${pending.discover.auth_base_url}${pending.discover.token_path}`
  const resp = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  })
  if (!resp.ok) throw new Error(`Token exchange failed: ${resp.status}`)
  const data = await resp.json()
  if (!data.access_token) throw new Error('access_token absent')
  clearPendingOAuth()
  return data.access_token
}
