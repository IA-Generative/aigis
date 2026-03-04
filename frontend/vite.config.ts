import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  define: {
    __VUE_PROD_DEVTOOLS__: true,
  },
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) }
  },
  server: {
    port: 5173,
    host: true,          // écoute sur 0.0.0.0 dans Docker
    hmr: {
      clientPort: 5173,  // port exposé côté hôte
    },
    watch: {
      usePolling: true,  // nécessaire dans certains environnements Docker/WSL
    },
  }
})

