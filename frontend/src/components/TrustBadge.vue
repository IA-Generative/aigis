<template>
  <span class="trust-badge" :class="cls">{{ score ?? '?' }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps({ score: { type: Number, default: null } })
const cls = computed(() => {
  if (props.score === null) return ''
  if (props.score >= 70) return 'high'
  if (props.score >= 40) return 'mid'
  return 'low'
})
</script>

<style scoped>
.trust-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 700;
}

.high {
  background: #d4edda;
  color: #155724;
}

.mid {
  background: #fff3cd;
  color: #856404;
}

.low {
  background: #f8d7da;
  color: #721c24;
}
</style>
