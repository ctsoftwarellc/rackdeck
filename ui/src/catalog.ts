import catalogData from "./catalog.json";

// One-click apps. Each is a single container so install is one `docker run`.
// Picked from what r/selfhosted and r/LocalLLaMA run (2025 survey, 2026 threads). Ports must not clash.

export type CatalogApp = {
  id: string; // also the container name
  name: string;
  blurb: string;
  category: "Media" | "Home" | "AI" | "Tools";
  image: string;
  hostPort: number; // the page you open
  containerPort: number;
  ports?: string[];
  volumes: string[]; // named volumes, so data survives updates and restarts
  /** Container path for a folder the person picks on that machine (their movies, music, books). */
  folder?: { path: string; label: string };
  /** Use NVIDIA GPUs when the machine has them. */
  gpu?: boolean;
  /** Shown before install, when something needs a heads-up. */
  note?: string;
  /** Install this way instead when the person picks a model server they already run (no bundled Ollama). */
  modelServer?: { image: string; volumes: string[] };
  /** Shown after install: the first thing to do. */
  next: string;
};

// The list itself is catalog.json, so the dashboard binary can offer the same apps to AI assistants.
export const CATALOG = catalogData as CatalogApp[];
