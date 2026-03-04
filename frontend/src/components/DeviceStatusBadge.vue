<template>
  <span class="badge" :class="status">{{ status }}</span>
</template>

<script setup lang="ts">
defineProps({ status: { type: String, default: '' } })
</script>

<style scoped>
.badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}

.active {
  background: #d4edda;
  color: #155724;
}

.pending_approval {
  background: #fff3cd;
  color: #856404;
}

.revoked {
  background: #f8d7da;
  color: #721c24;
}

.denied {
  background: #f8d7da;
  color: #721c24;
}
</style>
