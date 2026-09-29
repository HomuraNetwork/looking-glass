import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { Toaster } from "@/components/ui/sonner";
import { initTheme } from "@/lib/theme";
import "@/index.css";
import App from "@/App";

initTheme();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
      <Toaster richColors closeButton position="top-right" />
    </ErrorBoundary>
  </StrictMode>,
);
