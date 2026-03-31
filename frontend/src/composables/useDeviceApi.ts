import { apiFetch, DEVICE_SERVICE_BASE_URL } from '@/lib/api'
import { makeDeviceHeaders, makeSignature } from '@/lib/crypto'
import { useAuthStore } from '@/stores/auth'
import { useDeviceStore } from '@/stores/device'

export function useDeviceApi() {
  const auth = useAuthStore()
  const device = useDeviceStore()

  async function authHeader(includeSignature = false) {
    let headers = {}
    if (includeSignature) {
      headers = await makeDeviceHeaders(device.deviceId)
    }
    return { 'Authorization': `Bearer ${auth.accessToken}`, ...headers }
  }

  const register = async (payload) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...await authHeader() },
      body: JSON.stringify(payload)
    })

  const getStatus = async (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/status`, { headers: await authHeader() })

  const listMine = async () =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/me/devices`, { headers: await authHeader() })

  const listPending = async () =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/me/devices/pending`, { headers: await authHeader() })

  const getDeviceTrust = async (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/trust`, { headers: await authHeader() })

  const revoke = async (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/revoke`, {
      method: 'POST', headers: await authHeader()
    })

  const approve = async (deviceId, approverDeviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...await authHeader() },
      body: JSON.stringify({ approver_device_id: approverDeviceId })
    })

  const reject = async (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/reject`, {
      method: 'POST', headers: await authHeader()
    })

  const verifyEmailCode = async (deviceId, code) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/me/devices/${encodeURIComponent(deviceId)}/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...await authHeader() },
      body: JSON.stringify({ code })
    })

  const renewEmailCode = async (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/me/devices/${encodeURIComponent(deviceId)}/renew-code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...await authHeader() },
      body: JSON.stringify({ device_id: deviceId })
    })

  const verifyDevice = async (deviceId) => {
    const signature = await makeSignature()
    return apiFetch(`${DEVICE_SERVICE_BASE_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...await authHeader() },
      body: JSON.stringify({ 
        device_id: deviceId,
        ...signature,
      }),
    })
  }

  const reattest = async (deviceId, payload) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/reattest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...await authHeader() },
      body: JSON.stringify(payload)
    })

  const verifyDeviceByHeaders = async () =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/verify`, {
      method: 'GET',
      headers: await authHeader(true),
    })

  const verifyDeviceByApiKey = async (apiKey: string) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/verify`, {
      method: 'GET',
      headers: { 'x-api-key': apiKey },
      
    })

  return { 
    register, 
    getStatus,
    listMine,
    listPending,
    getDeviceTrust,
    revoke,
    approve,
    reject,
    verifyEmailCode,
    verifyDevice,
    reattest,
    verifyDeviceByHeaders,
    renewEmailCode,
    verifyDeviceByApiKey,
  }
}
