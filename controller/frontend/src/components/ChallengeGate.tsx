import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";

declare global {
  interface Window {
    turnstile?: {
      render: (
        element: HTMLElement,
        options: {
          sitekey: string;
          callback: (token: string) => void;
          "expired-callback": () => void;
          "error-callback": () => void;
          theme?: "light" | "dark" | "auto";
        },
      ) => string;
      reset: (widgetID?: string) => void;
      remove: (widgetID: string) => void;
    };
  }
}

export interface ChallengeGateHandle {
  reset: () => void;
}

interface Props {
  siteKey: string;
  onToken: (token: string) => void;
}

let turnstileScript: Promise<void> | null = null;

export const ChallengeGate = forwardRef<ChallengeGateHandle, Props>(function ChallengeGate({ siteKey, onToken }, ref) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const widgetRef = useRef<string>("");
  const [status, setStatus] = useState(siteKey ? "Loading challenge" : "Challenge not configured");

  useImperativeHandle(ref, () => ({
    reset() {
      onToken("");
      if (widgetRef.current) {
        window.turnstile?.reset(widgetRef.current);
      }
    },
  }));

  useEffect(() => {
    let mounted = true;
    onToken("");
    setStatus(siteKey ? "Loading challenge" : "Challenge not configured");
    if (!siteKey || !containerRef.current) return undefined;

    loadTurnstile()
      .then(() => {
        if (!mounted || !containerRef.current || !window.turnstile) return;
        const isDark = document.documentElement.dataset.theme === "dark";
        widgetRef.current = window.turnstile.render(containerRef.current, {
          sitekey: siteKey,
          theme: isDark ? "dark" : "light",
          callback: (token) => {
            onToken(token);
            setStatus("Verified");
          },
          "expired-callback": () => {
            onToken("");
            setStatus("Challenge expired");
          },
          "error-callback": () => {
            onToken("");
            setStatus("Challenge failed");
          },
        });
      })
      .catch(() => {
        if (mounted) setStatus("Challenge unavailable");
      });

    return () => {
      mounted = false;
      if (widgetRef.current) {
        window.turnstile?.remove(widgetRef.current);
        widgetRef.current = "";
      }
    };
  }, [siteKey, onToken]);

  return (
    <div className="w-full rounded-md border border-dashed bg-background p-2 text-center">
      <div ref={containerRef} className="flex min-h-16 justify-center" />
      <p className="mt-1 font-mono text-sm text-muted-foreground">{status}</p>
    </div>
  );
});

function loadTurnstile(): Promise<void> {
  if (window.turnstile) return Promise.resolve();
  if (turnstileScript) return turnstileScript;
  turnstileScript = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => {
      // Reset so the next mount can retry instead of caching the rejection forever.
      turnstileScript = null;
      reject(new Error("turnstile_script_failed"));
    };
    document.head.appendChild(script);
  });
  return turnstileScript;
}
