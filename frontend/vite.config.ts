import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { assetsDir: "static" },
  server: {
    strictPort: true,
    // Native Windows file watchers can fail with EBUSY when antivirus, sync,
    // or archive tools briefly lock a source file. Polling avoids attaching a
    // watcher handle to every file and keeps the local dashboard alive.
    watch: {
      usePolling: true,
      interval: 1000,
    },
    proxy: {
      "/api": "http://127.0.0.1:8765",
    },
  },
});
