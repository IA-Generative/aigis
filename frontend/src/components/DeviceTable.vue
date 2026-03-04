<template>
  <table class="device-table">
    <thead>
      <tr>
        <th>D. ID</th>
        <th>Name</th>
        <th>Status</th>
        <th>HW</th>
        <th>Trust</th>
        <th>Created</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="d in devices" :key="d.device_id" :class="{ current: d.device_id === currentDeviceId }">
        <td class="mono">{{ d.device_id.slice(0, 8) }}…</td>
        <td>{{ d.name || '—' }} <span v-if="d.device_id === currentDeviceId" class="you">(you)</span></td>
        <td>
          <DeviceStatusBadge :status="d.status" />
        </td>
        <td>
          <HwBadge :level="d.attestation_type" />
        </td>
        <td>
          <TrustBadge :score="d.trust_score ?? null" />
        </td>
        <td>{{ fmtDate(d.created_at) }}</td>
        <td class="actions">
          <template v-if="canManage">
            <button v-if="d.status === 'active'" class="btn-sm danger" @click="$emit('revoke', d.device_id)">Revoke</button>
            <button v-if="d.status === 'active'" class="btn-sm" @click="$emit('reattest', d.device_id)">Re-attest</button>
            <template v-if="d.status === 'pending_approval'">
              <button class="btn-sm ok" @click="$emit('approve', d.device_id)">Approve</button>
              <button class="btn-sm danger" @click="$emit('reject', d.device_id)">Reject</button>
            </template>
          </template>
          <span v-else class="muted">—</span>
        </td>
      </tr>
      <tr v-if="!devices.length">
        <td colspan="7" class="empty">No devices.</td>
      </tr>
    </tbody>
  </table>
</template>

<script setup lang="ts">
import DeviceStatusBadge from './DeviceStatusBadge.vue'
import HwBadge from './HwBadge.vue'
import TrustBadge from './TrustBadge.vue'

defineProps({
  devices: { type: Array, default: () => [] },
  currentDeviceId: { type: String, default: null },
  canManage: { type: Boolean, default: false },
})
defineEmits(['revoke', 'reattest', 'approve', 'reject'])

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}
</script>

<style scoped>
.device-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.device-table th,
.device-table td {
  border: 1px solid #dee2e6;
  padding: 6px 10px;
  text-align: left;
}

.device-table th {
  background: #f8f9fa;
}

.current {
  background: #fffbe6;
}

.mono {
  font-family: monospace;
}

.you {
  color: #6c757d;
  font-size: 11px;
}

.actions {
  white-space: nowrap;
}

.btn-sm {
  font-size: 11px;
  padding: 2px 8px;
  margin-right: 4px;
  cursor: pointer;
}

.ok {
  background: #d4edda;
  border-color: #c3e6cb;
}

.danger {
  background: #f8d7da;
  border-color: #f5c6cb;
}

.muted {
  color: #adb5bd;
}

.empty {
  text-align: center;
  color: #adb5bd;
}
</style>
