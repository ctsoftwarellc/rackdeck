import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    mode === "demo"
      ? {
          name: "rackdeck-demo-title",
          transformIndexHtml(html: string) {
            return html.replace(/<title>.*?<\/title>/, "<title>Rackdeck Live Demo</title>");
          },
        }
      : null,
  ].filter(Boolean),
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:7420", ws: true },
      "/mcp": "http://127.0.0.1:7420",
    },
  },
}));
