import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("unhandled app error", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <main className="flex min-h-dvh items-center justify-center bg-background px-4 text-foreground">
        <section className="w-full max-w-md rounded-lg border bg-card p-5" role="alert" aria-live="assertive">
          <h1 className="text-base font-bold">Something went wrong</h1>
          <p className="mt-2 text-sm text-muted-foreground">{this.state.error.message || "The app could not render this view."}</p>
          <Button className="mt-4" size="sm" onClick={() => globalThis.location.reload()}>
            Reload
          </Button>
        </section>
      </main>
    );
  }
}
