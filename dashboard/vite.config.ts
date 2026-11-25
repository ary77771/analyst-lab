// Builds the dashboard into engine/dashboard/static/app/, which the Python server hands out at
// /static/app/. Only that sub-folder is emptied on each build, so the vendored Cytoscape copy in
// static/vendor/ is never touched (debate 11, fresh review item 10).
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run dev` talks to a dashboard started on 8780 (development only). To look at your own copy without
// touching the demo's dashboards, start yours on another port and say which: `npx vite --mode api-8790`.
export default defineConfig(({ mode }) => ({
  base: "/static/app/",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../engine/dashboard/static/app",
    emptyOutDir: true,
    manifest: true,
    assetsInlineLimit: 0, // fonts stay files: the offline test can see them
  },
  server: {
    proxy: { "/api": `http://127.0.0.1:${/^api-(\d+)$/.exec(mode)?.[1] ?? "8780"}` },
  },
}));
