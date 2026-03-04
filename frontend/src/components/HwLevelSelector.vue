<template>
  <div class="selector">
    <label>Hardware level</label>
    <select :value="settings.hardwareLevel" @change="settings.setHardwareLevel($event.target.value as HardwareLevel)">
      <option value="auto">Auto-detect</option>
      <option value="none">Disabled (no key)</option>
      <option value="software">Software key</option>
      <option value="hardware">Hardware key (TPM/Secure Enclave)</option>
    </select>
  </div>
</template>

<script setup lang="ts">
import { useSettingsStore, type HardwareLevel } from '@/stores/settings.js'
const settings = useSettingsStore()
</script>
