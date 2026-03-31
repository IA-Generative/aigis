<template>
  <div class="button-row">
    <div>
      Verify Device
    </div>
    <div>
      <button :disabled="!device.deviceId" @click="callWithBody">
        Body
      </button>
      <button :disabled="!device.deviceId" @click="callWithHeaders">
        Headers
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useDeviceApi } from '@/composables/useDeviceApi';
import { useDeviceStore } from '@/stores/device';

const emits = defineEmits<{
  data: [data: any]
}>()

const api = useDeviceApi()
const device = useDeviceStore()
const deviceApi = useDeviceApi()

async function callWithBody() {
  try {
    const response = await api.verifyDevice(device.deviceId)
    emits('data', response)
  } catch (err) {
    emits('data', err.message ?? String(err))
    console.error('API Call Error:', err)
  }
}

async function callWithHeaders() {
  try {
    const response = await deviceApi.verifyDeviceByHeaders()
    emits('data', await response)
  } catch (err) {
    emits('data', err.message ?? String(err))
    console.error('API Auth Call Error:', err)
  }
}
</script>
