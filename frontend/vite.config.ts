import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    proxy: {
      '/auth': 'http://localhost:3000',
      '/model': 'http://localhost:3000', 
      '/health': 'http://localhost:3000'
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: true, // Enable source maps in both debug and release modes
    minify: mode === 'development' ? false : 'esbuild', // Skip minification in debug mode
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom']
        }
      }
    }
  },
  define: {
    __DEV__: mode === 'development'
  }
}))