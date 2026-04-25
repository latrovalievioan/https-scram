import { defineConfig } from 'vite'

export default defineConfig({
  root: './src',
  server: {
    fs: {
      allow: ['../crypto', '.']  // allows serving files from the parent directory
    },
    host: '0.0.0.0',
    port: 5173,
  }
})
