import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { decodeJWT, isTokenExpired } from '@/lib/api'

const ACCESS_TOKEN_KEY = 'device-service:access-token'
const DEVICE_ID_KEY = 'device-service:last-device-id'

export const useAuthStore = defineStore('auth', () => {
  const accessToken = ref(sessionStorage.getItem(ACCESS_TOKEN_KEY) || '')
  const deviceId = ref(localStorage.getItem(DEVICE_ID_KEY) || '')

  const isAuthenticated = computed(() => !!accessToken.value && !isTokenExpired(accessToken.value))

  const user = computed(() => {
    if (!accessToken.value) return null
    try { return decodeJWT(accessToken.value) } catch (_) { return null }
  })

  const username = computed(() => user.value?.preferred_username || user.value?.sub || '')

  function setToken(token) {
    accessToken.value = token
    sessionStorage.setItem(ACCESS_TOKEN_KEY, token)
  }

  function setDeviceId(id) {
    deviceId.value = id
    localStorage.setItem(DEVICE_ID_KEY, id)
  }

  function clear() {
    accessToken.value = ''
    deviceId.value = ''
    sessionStorage.removeItem(ACCESS_TOKEN_KEY)
    localStorage.removeItem(DEVICE_ID_KEY)
  }

  return {
    accessToken,
    deviceId,
    isAuthenticated,
    user,
    username,
    setToken,
    setDeviceId,
    clear
  }
})
