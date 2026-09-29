import { useState } from "react";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription, AlertDialogFooter,
  AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmPhrase: string;
  confirmLabel?: string;
  variant?: "destructive" | "default";
  onConfirm: () => void;
}

export function ConfirmDialog({
  open, onOpenChange, title, description,
  confirmPhrase, confirmLabel = "Confirm", variant = "default", onConfirm,
}: Props) {
  const [input, setInput] = useState("");
  const matches = input === confirmPhrase;

  function handleConfirm() {
    if (!matches) return;
    onConfirm();
    setInput("");
    onOpenChange(false);
  }

  function handleCancel() {
    setInput("");
    onOpenChange(false);
  }

  return (
    <AlertDialog open={open} onOpenChange={(v) => { if (!v) handleCancel(); }}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <div className="space-y-2 py-2">
          <Label className="text-sm">
            Type <span className="rounded bg-muted px-1 font-mono text-foreground">{confirmPhrase}</span> to confirm
          </Label>
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleConfirm()}
            placeholder={confirmPhrase}
            className="font-mono text-sm"
            autoFocus
          />
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={handleCancel}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={handleConfirm}
            disabled={!matches}
            className={variant === "destructive"
              ? "bg-destructive text-destructive-foreground hover:bg-destructive/90 disabled:opacity-40"
              : "disabled:opacity-40"}
          >
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
