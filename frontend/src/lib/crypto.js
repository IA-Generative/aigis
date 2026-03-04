/**
 * crypto.js — Web Crypto API + device-bound session signatures (ES module)
 */

const DB_NAME = 'device-crypto-keys'
const STORE_NAME = 'keys'
const KEY_ID = 'device-ecdsa-key'

// ── IndexedDB helpers ──────────────────────────────────────────────────────────
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function storeKeyPair(keyPair) {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    tx.objectStore(STORE_NAME).put(keyPair, KEY_ID)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

export async function loadKeyPair() {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const req = tx.objectStore(STORE_NAME).get(KEY_ID)
    req.onsuccess = () => resolve(req.result || null)
    req.onerror = () => reject(req.error)
  })
}

async function clearKeyPair() {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    tx.objectStore(STORE_NAME).delete(KEY_ID)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

// ── Key generation ─────────────────────────────────────────────────────────────
export async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // non-extractible
    ['sign', 'verify']
  )
  await storeKeyPair(keyPair)
  return keyPair
}

export async function getOrCreateKeyPair() {
  const kp = await loadKeyPair()
  if (kp?.privateKey && kp?.publicKey) return kp
  return generateKeyPair()
}

// ── Key export ─────────────────────────────────────────────────────────────────
export async function exportPublicKeyPEM(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey)
  const b64 = arrayBufferToBase64(spki)
  const lines = b64.match(/.{1,64}/g).join('\n')
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`
}

// ── Signing ────────────────────────────────────────────────────────────────────
export async function signPayload(privateKey, payload) {
  const data = new TextEncoder().encode(payload)
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data)
  return arrayBufferToBase64(signature)
}

export async function signChallenge(challenge) {
  const keyPair = await getOrCreateKeyPair()
  const nonce = crypto.randomUUID()
  const timestamp = new Date().toISOString()
  const signature = await signPayload(keyPair.privateKey, nonce + '|' + timestamp)
  return { nonce, timestamp, signature, challenge }
}

export async function signRegisterChallenge(challenge) {
  const keyPair = await getOrCreateKeyPair()
  const signature = await signPayload(keyPair.privateKey, challenge)
  return { challenge, signature }
}

// ── Device-bound session headers ───────────────────────────────────────────────
export async function makeDeviceHeaders(deviceId) {
  if (!deviceId) return {}
  try {
    const kp = await loadKeyPair()
    if (!kp?.privateKey) return {}
    const nonce = crypto.randomUUID()
    const timestamp = new Date().toISOString()
    const signature = await signPayload(kp.privateKey, nonce + '|' + timestamp)
    return { 'X-Device-ID': deviceId, 'X-Device-Nonce': nonce, 'X-Device-Timestamp': timestamp, 'X-Device-Signature': signature }
  } catch (_) {
    return {}
  }
}

// ── Hardware detection ─────────────────────────────────────────────────────────
export async function detectHardwareLevel() {
  try {
    if (!window.PublicKeyCredential) return { level: 'software', provider: 'software' }
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    if (available) {
      const p = navigator.platform || ''
      let provider = 'tee'
      if (/Mac|iPhone|iPad/.test(p)) provider = 'secure_enclave'
      else if (/Win/.test(p)) provider = 'tpm'
      else if (/Linux/.test(p)) provider = 'tpm'
      return { level: 'tee', provider }
    }
    return { level: 'software', provider: 'software' }
  } catch (_) {
    return { level: 'software', provider: 'software' }
  }
}

// ── Utils ──────────────────────────────────────────────────────────────────────
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach(b => binary += String.fromCharCode(b))
  return btoa(binary)
}

export async function resetKeys() {
  await clearKeyPair()
}
