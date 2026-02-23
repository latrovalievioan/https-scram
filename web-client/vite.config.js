import { defineConfig } from 'vite'

export default defineConfig({
  root: '.',
  server: {
    fs: {
      allow: ['../crypto', '../web-client']  // allows serving files from the parent directory
    }
  }
})
