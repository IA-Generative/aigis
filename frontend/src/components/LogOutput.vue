<template>
  <textarea readonly :value="content" placeholder="— logs —"></textarea>
</template>

<script setup lang="ts">
defineProps({ content: { type: String, default: '' } })
</script>

<style scoped>
textarea {
  width: 100%;
  height: 220px;
  font-family: monospace;
  font-size: 12px;
  resize: vertical;
  box-sizing: border-box;
}
</style>
