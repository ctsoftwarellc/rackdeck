import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

async function boot() {
  if (import.meta.env.MODE === "demo") {
    const { installDemo } = await import("./demo");
    installDemo();
  }
  createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}

void boot();
