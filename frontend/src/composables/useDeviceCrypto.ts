import { apiFetch, DEVICE_SERVICE_BASE_URL } from '@/lib/api'
import { useAuthStore } from '@/stores/auth'
import { useSettingsStore } from '@/stores/settings'
import {
  getOrCreateKeyPair, exportPublicKeyPEM, signRegisterChallenge,
  signChallenge, detectHardwareLevel, loadKeyPair, resetKeys, makeDeviceHeaders as _makeDeviceHeaders
} from '@/lib/crypto'

export function useDeviceCrypto() {
  const auth = useAuthStore()
  const settings = useSettingsStore()

  /**
   * Full register ceremony: challenge → key → sign → return payload fields
   * hwMode: 'auto' | 'none' | 'software' | 'hardware'
   */
  async function buildRegisterPayload(accessToken: string) {
    const hwMode = settings.hardwareLevel
    let publicKeyPEM = '', keyAlgorithm = '', hardwareLevel = 'software',
      providerName = 'software', challenge = '', challengeSignature = ''

    if (hwMode === 'none') return { publicKeyPEM, keyAlgorithm, hardwareLevel, providerName, challenge, challengeSignature }

    try {
      const challengeResp = await apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/register/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` }
      })
      challenge = challengeResp.challenge

      const keyPair = await getOrCreateKeyPair()
      publicKeyPEM = await exportPublicKeyPEM(keyPair.publicKey)
      keyAlgorithm = 'ES256'

      const signResult = await signRegisterChallenge(challenge)
      challengeSignature = signResult.signature

      if (hwMode === 'software') {
        hardwareLevel = 'software'; providerName = 'software'
      } else {
        const hwInfo = await detectHardwareLevel()
        hardwareLevel = hwInfo.level; providerName = hwInfo.provider
      }
    } catch (err) {
      console.warn('Attestation ceremony failed:', err.message)
      return { publicKeyPEM: '', keyAlgorithm: '', hardwareLevel: 'software', providerName: 'software', challenge: '', challengeSignature: '' }
    }

    return { 
      public_key: publicKeyPEM, 
      key_algorithm: keyAlgorithm, 
      hardware_level: hardwareLevel, 
      provider_name: providerName, 
      challenge, 
      challenge_signature: challengeSignature }
  }

  async function buildReattestPayload(deviceId, accessToken) {
    const challengeResp = await apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/challenge`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}` }
    })
    const signData = await signChallenge(challengeResp.challenge)
    const hwInfo = await detectHardwareLevel()

    let publicKeyPEM = ''
    try {
      const kp = await loadKeyPair()
      if (kp?.publicKey) publicKeyPEM = await exportPublicKeyPEM(kp.publicKey)
    } catch (_) {}

    return {
      signature: signData.signature,
      timestamp: signData.timestamp,
      nonce: signData.nonce,
      public_key: publicKeyPEM,
      key_algorithm: 'ES256',
      hardware_level: hwInfo.level,
      provider_name: hwInfo.provider
    }
  }

  async function makeDeviceHeaders(deviceId) {
    return _makeDeviceHeaders(deviceId)
  }

  async function reset() {
    auth.setDeviceId('')
    await resetKeys()
  }

  return { buildRegisterPayload, buildReattestPayload, makeDeviceHeaders, reset }
}
