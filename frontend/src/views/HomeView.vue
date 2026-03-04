<template>
  <div>
    <h1>Device Flow</h1>
    <div class="two-col">

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

        <div v-if="auth.user" class="jwt-panel">
          <div class="jwt-title">JWT Payload</div>
          <pre class="jwt-pre">{{ JSON.stringify(auth.user, null, 2) }}</pre>
        </div>
      </div>

      <!-- ── COLONNE DROITE : Device ────────────────────────────────────── -->
      <div class="panel">
        <h2>Enregistrement device</h2>
        <HwLevelSelector /> {{ settings.hardwareLevel }}

        <div class="row">
          <button :disabled="!auth.isAuthenticated || busy" @click="doRegister">
            Enregistrer ce device
          </button>
          <button :disabled="!auth.isAuthenticated || !auth.deviceId || busy" @click="fakeCall">
            Fake API Call
          </button>
          <button @click="reset">Reset</button>
        </div>

        <StatusBanner v-if="deviceStatusMsg" :type="deviceStatusType" :message="deviceStatusMsg" />
        <PendingApprovalPanel v-if="pendingDeviceId" :device-id="pendingDeviceId" @approved="onApproved" />

        <div v-if="auth.deviceId" class="device-info">
          <div class="device-info-title">Device actif</div>
          <code>{{ auth.deviceId }}</code>
        </div>

        <DebugPanel :data="debugData" />
        <LogOutput :content="logContent" />
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import HwLevelSelector from '@/components/HwLevelSelector.vue'
import StatusBanner from '@/components/StatusBanner.vue'
import PendingApprovalPanel from '@/components/PendingApprovalPanel.vue'
import DebugPanel from '@/components/DebugPanel.vue'
import LogOutput from '@/components/LogOutput.vue'
import { useAuthStore } from '@/stores/auth.js'
import { useSettingsStore } from '@/stores/settings.js'
import { useOAuth } from '@/composables/useOAuth.js'
import { useDeviceCrypto } from '@/composables/useDeviceCrypto.js'
import { useDeviceApi } from '@/composables/useDeviceApi.js'

const auth = useAuthStore()
const settings = useSettingsStore()
const oauth = useOAuth()
const deviceCrypto = useDeviceCrypto()
const api = useDeviceApi()

const busy = ref(false)

// Auth column status
const authStatusMsg = ref('')
const authStatusType = ref('info')

// Device column status
const deviceStatusMsg = ref('')
const deviceStatusType = ref('info')

const pendingDeviceId = ref<string | null>(null)
const debugData = ref({})
const logLines = ref<string[]>([])
const logContent = ref('')

function log(label: string, data: unknown) {
  const line = `[${label}] ${typeof data === 'object' ? JSON.stringify(data) : data}`
  logLines.value.push(line)
  logContent.value = logLines.value.join('\n')
}

function setAuthStatus(type: string, msg: string) {
  authStatusType.value = type
  authStatusMsg.value = msg
}

function setDeviceStatus(type: string, msg: string) {
  deviceStatusType.value = type
  deviceStatusMsg.value = msg
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

// ── Device actions ────────────────────────────────────────────────────────────
async function doRegister() {
  busy.value = true
  setDeviceStatus('info', 'Enregistrement du device…')
  try {
    const payload = await deviceCrypto.buildRegisterPayload(auth.accessToken)
    debugData.value = { ...payload, public_key: payload.public_key ? payload.public_key.slice(0, 40) + '…' : '' }

    const result = await api.register({
      ...payload,
      device_id: auth.deviceId,
      name: navigator.userAgent.slice(0, 64),
      user_agent: navigator.userAgent,
      platform: navigator.platform || 'browser',
    })
    auth.setDeviceId(result.device_id)
    log('REGISTER', result)

    if (result.device_status === 'pending_approval') {
      pendingDeviceId.value = result.device_id
      setDeviceStatus('warn', 'Appareil enregistré — en attente d\'approbation.')
    } else {
      setDeviceStatus('ok', `Appareil actif ! (${result.device_id.slice(0, 8)}…)`)
    }
  } catch (err: any) {
    setDeviceStatus('ko', err.message)
    log('ERROR', err.message)
  } finally {
    busy.value = false
  }
}

async function fakeCall() {
  try {
    const headers = await deviceCrypto.makeDeviceHeaders(auth.deviceId)
    log('FAKE CALL', headers)
    setDeviceStatus('ok', 'Headers device affichés dans le log.')
  } catch (err: any) {
    setDeviceStatus('ko', err.message)
  }
}

function onApproved() {
  pendingDeviceId.value = null
  setDeviceStatus('ok', '✅ Appareil approuvé !')
}

function reset() {
  // auth.clear()
  deviceCrypto.reset()
  logLines.value = []
  logContent.value = ''
  debugData.value = {}
  pendingDeviceId.value = null
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

.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  align-items: start;
}

@media (max-width: 700px) {
  .two-col {
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
  max-height: 300px;
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
