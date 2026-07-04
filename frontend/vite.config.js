import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During `npm run dev`, API calls go to the backend. Set VITE_API_BASE to point
// at it (defaults to http://localhost:8000). When the dashboard is built and
// served by FastAPI itself, leave VITE_API_BASE empty for same-origin calls.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});
