import { createRouter, createWebHistory } from 'vue-router'
import HomeView        from '@/views/HomeView.vue'
import DevicesView     from '@/views/DevicesView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/',             component: HomeView        },
    { path: '/devices',      component: DevicesView     },
  ],
})
