import { apiFetch, DEVICE_SERVICE_BASE_URL } from '@/lib/api'
import { useAuthStore } from '@/stores/auth'

export function useDeviceApi() {
  const auth = useAuthStore()

  function authHeader() {
    return { 'Authorization': `Bearer ${auth.accessToken}` }
  }

  const register = (payload) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify(payload)
    })

  const getStatus = (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/status`)

  const listMine = () =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/me/devices`, { headers: authHeader() })

  const listPending = () =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/me/devices/pending`, { headers: authHeader() })

  const getDeviceTrust = (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/trust`, { headers: authHeader() })

  const revoke = (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/revoke`, {
      method: 'POST', headers: authHeader()
    })

  const approve = (deviceId, approverDeviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify({ approver_device_id: approverDeviceId })
    })

  const reject = (deviceId) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/reject`, {
      method: 'POST', headers: authHeader()
    })

  const verifyEmailCode = (deviceId, code) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/me/devices/${encodeURIComponent(deviceId)}/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify({ code })
    })

  const reattest = (deviceId, payload) =>
    apiFetch(`${DEVICE_SERVICE_BASE_URL}/devices/${encodeURIComponent(deviceId)}/reattest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify(payload)
    })

  return { register, getStatus, listMine, listPending, getDeviceTrust, revoke, approve, reject, verifyEmailCode, reattest }
}
