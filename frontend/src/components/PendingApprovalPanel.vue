<template>
  <div class="pending-panel">
    <p>
      Un code de vérification a été envoyé à votre adresse email.
      Entrez-le ci-dessous pour approuver le device <strong>{{ deviceId.slice(0, 8) }}…</strong>,
      ou attendez qu'un autre appareil de confiance l'approuve.
    </p>
    <form class="verify-form" @submit.prevent="submitCode">
      <input v-model="code" type="text" inputmode="numeric" maxlength="6" placeholder="Code à 6 chiffres"
        :disabled="busy" autocomplete="one-time-code" />
      <button type="submit" :disabled="busy || code.length < 6">
        {{ busy ? 'Vérification…' : 'Valider le code' }}
      </button>
    </form>
    <StatusBanner v-if="msg" :type="msgType" :message="msg" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import StatusBanner from './StatusBanner.vue'
import { useDeviceApi } from '@/composables/useDeviceApi.js'

const props = defineProps({ deviceId: { type: String, required: true } })
const emit = defineEmits(['approved'])

const api = useDeviceApi()

const code = ref('')
const busy = ref(false)
const msg = ref('')
const msgType = ref('info')

let pollTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  pollTimer = setInterval(poll, 8000)
})
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })

async function poll() {
  try {
    const d = await api.getStatus(props.deviceId)
    if (d.status === 'active') {
      if (pollTimer) clearInterval(pollTimer)
      emit('approved')
    }
  } catch (_) { /* ignore */ }
}

async function submitCode() {
  busy.value = true
  msg.value = ''
  try {
    await api.verifyEmailCode(props.deviceId, code.value)
    if (pollTimer) clearInterval(pollTimer)
    msgType.value = 'ok'
    msg.value = 'Device approuvé !'
    emit('approved')
  } catch (err: any) {
    msgType.value = 'ko'
    msg.value = err.message ?? String(err)
  } finally {
    busy.value = false
  }
}
</script>

<style scoped>
.pending-panel {
  border: 1px solid #f0ad4e;
  border-radius: 6px;
  padding: 12px;
  margin: 8px 0;
}

.verify-form {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-top: 8px;
}

.verify-form input {
  width: 140px;
  padding: 6px 10px;
  font-size: 1.1rem;
  letter-spacing: 0.3em;
  text-align: center;
  border: 1px solid #ced4da;
  border-radius: 4px;
}

.verify-form button {
  white-space: nowrap;
}
</style>
