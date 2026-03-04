<template>
  <span class="hw-badge" :class="level">{{ label }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps({ level: { type: String, default: '' } })
const label = computed(() => {
  switch (props.level) {
    case 'hardware': return 'HW'
    case 'software': return 'SW'
    case 'none': return 'NONE'
    default: return props.level || '?'
  }
})
</script>

<style scoped>
.hw-badge {
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
}

.hardware {
  background: #cfe2ff;
  color: #084298;
}

.software {
  background: #e2e3e5;
  color: #343a40;
}

.none {
  background: #f8d7da;
  color: #721c24;
}
</style>
