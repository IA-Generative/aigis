<template>
  <div>
    <h1>Mes appareils</h1>
    <StatusBanner v-if="banner.msg" :type="banner.type" :message="banner.msg" />

    <div v-if="trustWarning" class="trust-gate">
      🔒 <strong>Accès restreint</strong> — Score de confiance insuffisant ({{ trustScore }}/100 &lt; 70).
      Effectuez une re-attestation pour augmenter votre score.
    </div>

    <!-- Pending devices section (for trusted device managing others) -->
    <div v-if="pendingDevices.length && canManage" class="pending-section">
      <h3>⚠️ Appareils en attente d'approbation</h3>
      <div v-for="d in pendingDevices" :key="d.device_id" class="pending-card">
        <div class="info">
          <strong>{{ d.name || 'Nouvel appareil' }}</strong>
          <span class="id mono">{{ d.device_id }}</span><br />
          <small>{{ d.platform || '?' }} — {{ fmtDate(d.created_at) }}</small>
        </div>
        <div class="actions">
          <button class="btn-sm ok" @click="approve(d.device_id)">✅ Approuver</button>
          <button class="btn-sm danger" @click="reject(d.device_id)">❌ Rejeter</button>
        </div>
      </div>
    </div>

    <p>
      <button @click="load">🔄 Rafraîchir</button>
    </p>

    <DeviceTable :devices="devices" :current-device-id="currentDeviceId" :can-manage="canManage" @revoke="revoke"
      @reattest="reattest" @approve="approve" @reject="reject" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import StatusBanner from '@/components/StatusBanner.vue'
import DeviceTable from '@/components/DeviceTable.vue'
import { useAuthStore } from '@/stores/auth.js'
import { useDeviceApi } from '@/composables/useDeviceApi.js'
import { useDeviceCrypto } from '@/composables/useDeviceCrypto.js'

const auth = useAuthStore()
const api = useDeviceApi()
const crypto = useDeviceCrypto()

const banner = ref({ type: 'info', msg: 'Chargement…' })
const devices = ref([])
const pendingDevices = ref([])
const trustScore = ref(null)
const trustWarning = ref(false)
const canManage = ref(false)

const currentDeviceId = computed(() => auth.deviceId)

let pollTimer = null

onMounted(async () => {
  if (!auth.isAuthenticated) {
    banner.value = { type: 'ko', msg: 'Non authentifié. Retournez sur la page d\'accueil.' }
    return
  }
  await load()
  pollTimer = setInterval(async () => {
    if (canManage.value) await loadPending()
  }, 10000)
})
onUnmounted(() => clearInterval(pollTimer))

async function load() {
  banner.value = { type: 'info', msg: 'Chargement…' }
  try {
    // check trust
    if (currentDeviceId.value) {
      try {
        const trust = await api.getDeviceTrust(currentDeviceId.value)
        trustScore.value = trust.trust_score
        canManage.value = trust.trust_score >= 70
        trustWarning.value = !canManage.value
      } catch (_) { canManage.value = false }
    }

    const list = await api.listMine()
    devices.value = (list || []).filter(d => d.status !== 'revoked')

    if (canManage.value) await loadPending()

    const user = auth.username || auth.user?.sub || '?'
    const extra = trustScore.value !== null ? ` — Score confiance: ${trustScore.value}/100` : ''
    banner.value = { type: canManage.value ? 'ok' : 'warn', msg: `Connecté en tant que ${user}${extra}` }
  } catch (err) {
    banner.value = { type: 'ko', msg: err.message }
  }
}

async function loadPending() {
  try {
    const list = await api.listPending()
    pendingDevices.value = list || []
  } catch (_) { pendingDevices.value = [] }
}

async function revoke(deviceId: string) {
  if (!confirm(`Révoquer l'appareil ${deviceId} ?`)) return
  try {
    await api.revoke(deviceId)
    await load()
  } catch (err) { banner.value = { type: 'ko', msg: err.message } }
}

async function approve(deviceId: string) {
  try {
    await api.approve(deviceId, currentDeviceId.value)
    await load()
    banner.value = { type: 'ok', msg: `Appareil approuvé !` }
  } catch (err) { banner.value = { type: 'ko', msg: err.message } }
}

async function reject(deviceId: string) {
  if (!confirm(`Rejeter l'appareil ${deviceId} ?`)) return
  try {
    await api.reject(deviceId)
    await load()
    banner.value = { type: 'ok', msg: `Appareil rejeté.` }
  } catch (err) { banner.value = { type: 'ko', msg: err.message } }
}

async function reattest(deviceId: string) {
  try {
    banner.value = { type: 'info', msg: 'Re-attestation en cours…' }
    const payload = await crypto.buildReattestPayload(deviceId, auth.accessToken)
    const result = await api.reattest(deviceId, payload)
    banner.value = { type: 'ok', msg: `Re-attestation réussie ! Score: ${result.trust_score ?? '?'}/100` }
    await load()
  } catch (err) { banner.value = { type: 'ko', msg: err.message } }
}

function fmtDate(iso: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })
}
</script>

<style scoped>
.trust-gate {
  margin-bottom: 16px;
  padding: 14px 18px;
  border-radius: 8px;
  background: #fff3f3;
  border: 1px solid #f0c9c9;
  color: #7a2222;
  font-size: 14px;
}

.pending-section {
  margin-top: 16px;
  padding: 12px;
  border-radius: 8px;
  background: #fffce6;
  border: 1px solid #f0dca0;
}

.pending-section h3 {
  margin: 0 0 10px;
  font-size: 15px;
  color: #856404;
}

.pending-card {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  border-radius: 6px;
  background: #fff;
  border: 1px solid #e8e0c0;
  margin-bottom: 6px;
}

.pending-card .info .id {
  font-family: monospace;
  font-size: 11px;
  color: #666;
}

.actions {
  display: flex;
  gap: 6px;
}

.btn-sm {
  font-size: 11px;
  padding: 3px 10px;
  cursor: pointer;
  border-radius: 4px;
  border: 1px solid #ccc;
}

.ok {
  background: #d4edda;
  border-color: #c3e6cb;
}

.danger {
  background: #f8d7da;
  border-color: #f5c6cb;
}
</style>
