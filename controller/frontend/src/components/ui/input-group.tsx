import * as React from "react";
import { cn } from "@/lib/utils";

const InputGroup = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "flex min-w-0 items-center rounded-md border border-input bg-background shadow-sm transition-colors focus-within:ring-1 focus-within:ring-ring",
        className,
      )}
      {...props}
    />
  ),
);
InputGroup.displayName = "InputGroup";

const InputGroupInput = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      data-slot="input-group-control"
      className={cn(
        "min-w-0 flex-1 bg-transparent px-3 py-1 text-sm outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
);
InputGroupInput.displayName = "InputGroupInput";

const InputGroupAddon = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { align?: "inline-start" | "inline-end" }
>(({ className, align = "inline-start", ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      "flex shrink-0 items-center gap-1 px-1.5",
      align === "inline-start" ? "order-first" : "order-last",
      className,
    )}
    {...props}
  />
));
InputGroupAddon.displayName = "InputGroupAddon";

const InputGroupButton = React.forwardRef<HTMLButtonElement, React.ButtonHTMLAttributes<HTMLButtonElement>>(
  ({ className, type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(
        "inline-flex h-7 items-center justify-center gap-1 rounded px-2 text-xs font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
        className,
      )}
      {...props}
    />
  ),
);
InputGroupButton.displayName = "InputGroupButton";

const InputGroupText = React.forwardRef<HTMLSpanElement, React.HTMLAttributes<HTMLSpanElement>>(
  ({ className, ...props }, ref) => (
    <span ref={ref} className={cn("text-xs text-muted-foreground", className)} {...props} />
  ),
);
InputGroupText.displayName = "InputGroupText";

export { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput, InputGroupText };
