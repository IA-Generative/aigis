import { defineStore } from 'pinia'
import { ref } from 'vue'

const HARDWARE_LEVEL = 'device-service:hardware-level'

export type HardwareLevel = 'auto' | 'none' | 'software' | 'hardware'
export const useSettingsStore = defineStore('settings', () => {
  const hardwareLevel = ref<HardwareLevel>(sessionStorage.getItem(HARDWARE_LEVEL) as HardwareLevel || 'auto')

  function setHardwareLevel(level: HardwareLevel) {
    hardwareLevel.value = level
    sessionStorage.setItem(HARDWARE_LEVEL, level)
  }

  return {
    hardwareLevel,
    setHardwareLevel,
  }
})
