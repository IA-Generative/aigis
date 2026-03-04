<template>
  <div class="status-banner" :class="type">{{ message }}</div>
</template>

<script setup lang="ts">
defineProps({
  type: { type: String, default: 'ko' }, // ok | ko | info | warn
  message: { type: String, default: '' }
})
</script>

<style scoped>
.status-banner {
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 14px;
  min-height: 1.5em;
}

.ok {
  background: #eefaf1;
  border: 1px solid #b9e2c3;
  color: #1f5130;
}

.ko {
  background: #fff3f3;
  border: 1px solid #f0c9c9;
  color: #7a2222;
}

.info {
  background: #f0f4ff;
  border: 1px solid #b3c6f0;
  color: #1a3a7a;
}

.warn {
  background: #fff8e1;
  border: 1px solid #f0dca0;
  color: #7a6318;
}
</style>
