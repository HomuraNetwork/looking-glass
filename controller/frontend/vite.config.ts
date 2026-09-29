import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8787",
    },
  },
  resolve: {
    alias: {
      "@": "/src",
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Only split React itself into a stable long-cache chunk. Hand-splitting
        // the rest of the vendor graph (radix/icons) creates circular chunks
        // (vendor-radix -> vendor-react -> vendor-radix) because those packages
        // depend on react while sharing modules with it; Rollup's default
        // splitting plus the lazy AdminPanel chunk is safer and nearly as good.
        manualChunks(id) {
          if (id.includes("node_modules")) {
            if (id.includes("react-dom") || /node_modules[\\/]react[\\/]/.test(id) || id.includes("scheduler")) {
              return "vendor-react";
            }
          }
        },
      },
    },
  },
});
