<template>
  <textarea readonly :value="formatted" placeholder="— debug —"></textarea>
</template>

<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps({ data: { type: Object, default: () => ({}) } })
const formatted = computed(() => JSON.stringify(props.data, null, 2))
</script>

<style scoped>
textarea {
  width: 100%;
  height: 100px;
  font-family: monospace;
  font-size: 11px;
  color: #555;
  resize: vertical;
  box-sizing: border-box;
}
</style>
