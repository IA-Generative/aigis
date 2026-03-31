<template>
  <div class="grid">
    <h1 style="grid-column: 1 / 2 span;">Device Flow</h1>

    <!-- ── COLONNE GAUCHE : Authentification ──────────────────────────── -->
    <div class="panel">
      <h2>Connexion Keycloak</h2>

      <div class="row">
        <button :disabled="busy" @click="startRedirect">
          Connexion
        </button>
      </div>

      <div class="danger-zone">
        <button :disabled="!auth.isAuthenticated" @click="logout">Se déconnecter</button>
      </div>

      <div class="auth-status" :class="auth.isAuthenticated ? 'ok' : 'ko'">
        <template v-if="auth.isAuthenticated">
          ✅ Connecté — <strong>{{ auth.username }}</strong>
        </template>
        <template v-else>⛔ Non connecté</template>
      </div>

      <StatusBanner v-if="authStatusMsg" :type="authStatusType" :message="authStatusMsg" />
    </div>
    <div class="panel">
      <div v-if="auth.user" class="jwt-panel">
        <div class="jwt-title">JWT Payload</div>
        <pre class="jwt-pre">{{ JSON.stringify(auth.user, null, 2) }}</pre>
      </div>
    </div>

    <!-- ── COLONNE DROITE : Device ────────────────────────────────────── -->
    <div class="panel">
      <h2>Enregistrement device</h2>
      <HwLevelSelector />

      <div class="col">
        <RegisterButton @reset="reset" @data="(data) => debugData = data" />
        <ApiCallButton @data="(data) => debugData = data" />
        <StatusButton @data="(data) => debugData = data" />
        <HeadersButton @data="(data) => debugData = data" />
        <VerifyButton @data="(data) => debugData = data" />
        <ApiKeyForm @data="(data) => debugData = data" />
      </div>

      <StatusBanner v-if="deviceStatusMsg" :type="deviceStatusType" :message="deviceStatusMsg" />
      <PendingApprovalPanel v-if="home.pendingDeviceId" :device-id="home.pendingDeviceId" @approved="onApproved" />

      <div v-if="device.deviceId" class="device-info">
        <div class="device-info-title">{{ device.device?.status ?? 'Inconnu' }}</div>
        <code>{{ device.deviceId }}</code>
      </div>

    </div>
    <div class="panel">
      <DebugPanel :data="debugData" />
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import HwLevelSelector from '@/components/HwLevelSelector.vue'
import StatusBanner from '@/components/StatusBanner.vue'
import PendingApprovalPanel from '@/components/PendingApprovalPanel.vue'
import DebugPanel from '@/components/DebugPanel.vue'
import { useAuthStore } from '@/stores/auth.js'
import { useOAuth } from '@/composables/useOAuth.js'
import { useDeviceApi } from '@/composables/useDeviceApi.js'
import ApiCallButton from '@/components/ApiCallButton.vue'
import StatusButton from '@/components/StatusButton.vue'
import VerifyButton from '@/components/VerifyButton.vue'
import HeadersButton from '@/components/HeadersButton.vue'
import { useDeviceStore } from '@/stores/device'
import RegisterButton from '@/components/RegisterButton.vue'
import { useDeviceCrypto } from '@/composables/useDeviceCrypto'
import { useHomeStore } from '@/stores/home'

const auth = useAuthStore()
const device = useDeviceStore()
const home = useHomeStore()
const oauth = useOAuth()
const api = useDeviceApi()

const busy = ref(false)

// Auth column status
const authStatusMsg = ref('')
const authStatusType = ref('info')

// Device column status
const deviceStatusMsg = ref('')
const deviceStatusType = ref('info')

const debugData = ref({})
const logLines = ref<string[]>([])

function log(label: string, data: unknown) {
  const line = `[${label}] ${typeof data === 'object' ? JSON.stringify(data) : data}`
  logLines.value.push(line)
}

function setAuthStatus(type: string, msg: string) {
  authStatusType.value = type
  authStatusMsg.value = msg
}

function onApproved() {
  home.pendingDeviceId = null
  setDeviceStatus('ok', '✅ Appareil approuvé !')
}

function setDeviceStatus(type: string, msg: string) {
  home.deviceStatusType = type
  home.deviceStatusMsg = msg
}

// ── OAuth callback on page load ───────────────────────────────────────────────
// Échange le code → stocke le token, mais N'enregistre PAS le device automatiquement.
onMounted(async () => {
  if (!window.location.search.includes('code=')) return

  try {
    busy.value = true
    setAuthStatus('info', 'Traitement du callback OAuth…')
    const token = await oauth.handleCallback()
    if (!token) { busy.value = false; return }

    setAuthStatus('ok', `Connecté en tant que ${auth.username}. Vous pouvez maintenant enregistrer ce device.`)
  } catch (err: any) {
    setAuthStatus('ko', err.message)
    log('ERROR', err.message)
  } finally {
    busy.value = false
  }

  if (device.deviceId) {
    const status = await api.getStatus(device.deviceId)
    device.setDevice(status)
    console.log('Device status on load:', status)
  }
})

// ── Auth actions ──────────────────────────────────────────────────────────────
async function startRedirect() {
  busy.value = true
  setAuthStatus('info', 'Redirection vers Keycloak…')
  try {
    await oauth.redirectToLogin()
  } catch (err: any) {
    setAuthStatus('ko', err.message)
    busy.value = false
  }
}

async function logout() {
  try {
    await oauth.logout()
  } catch (err: any) {
    setAuthStatus('ko', err.message)
  }
}
const deviceCrypto = useDeviceCrypto()

function reset() {
  // auth.clear()
  deviceCrypto.reset()
  logLines.value = []
  debugData.value = {}
  home.pendingDeviceId = null
  authStatusMsg.value = ''
  deviceStatusMsg.value = ''
}
</script>

<style scoped>
h1 {
  margin-bottom: 16px;
}

h2 {
  margin: 0 0 12px;
  font-size: 1rem;
  font-weight: 600;
  color: #495057;
  border-bottom: 1px solid #dee2e6;
  padding-bottom: 8px;
}

.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

@media (max-width: 700px) {
  .grid {
    grid-template-columns: 1fr;
  }
}

.panel {
  background: #fff;
  border: 1px solid #dee2e6;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: flex-end;
}

.col {
  display: flex;
  flex-direction: column;
  gap: 10px;
  align-items: flex-start;
}

.danger-zone {
  display: flex;
  gap: 8px;
}

.auth-status {
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.auth-status.ok {
  background: #d1fae5;
  color: #065f46;
}

.auth-status.ko {
  background: #fee2e2;
  color: #991b1b;
}

.jwt-panel {
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  overflow: hidden;
}

.jwt-title {
  background: #f8fafc;
  padding: 4px 10px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #64748b;
  border-bottom: 1px solid #e2e8f0;
}

.jwt-pre {
  margin: 0;
  padding: 10px;
  font-size: 0.7rem;
  line-height: 1.5;
  overflow-x: auto;
  max-height: 250px;
  overflow-y: auto;
  background: #fff;
}

.device-info {
  padding: 8px 12px;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  border-radius: 6px;
  font-size: 0.875rem;
}

.device-info-title {
  font-weight: 600;
  font-size: 0.75rem;
  color: #15803d;
  margin-bottom: 4px;
}
</style>
