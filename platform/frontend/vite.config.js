import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, proxy /api to the backend; in prod, nginx does the same.
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
