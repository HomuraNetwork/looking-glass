import { Plus, Trash2, ArrowUp, ArrowDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import type { PublicNavItem } from "@/lib/api";

export function NavItemsEditor({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const items = parseNavItems(value);
  function update(next: PublicNavItem[]) {
    onChange(JSON.stringify(next, null, 2));
  }
  function patch(index: number, patchValue: Partial<PublicNavItem>) {
    update(items.map((item, itemIndex) => {
      if (itemIndex === index) return { ...item, ...patchValue };
      return patchValue.active === true ? { ...item, active: undefined } : item;
    }));
  }
  function move(index: number, direction: -1 | 1) {
    const newIndex = index + direction;
    if (newIndex < 0 || newIndex >= items.length) return;
    const next = [...items];
    [next[index], next[newIndex]] = [next[newIndex], next[index]];
    update(next);
  }
  return (
    <div className="flex flex-col gap-2">
      {items.map((item, index) => (
        <div key={index} className="rounded-lg border bg-background/70 p-2">
          <div className="grid gap-2 md:grid-cols-[auto_minmax(0,0.9fr)_minmax(0,1.3fr)_minmax(5rem,0.5fr)_auto]">
            <div className="flex flex-col gap-1">
              <Button type="button" size="icon" variant="ghost" className="h-4 w-6"
                onClick={() => move(index, -1)} disabled={index === 0} aria-label="Move up">
                <ArrowUp className="size-3" />
              </Button>
              <Button type="button" size="icon" variant="ghost" className="h-4 w-6"
                onClick={() => move(index, 1)} disabled={index === items.length - 1} aria-label="Move down">
                <ArrowDown className="size-3" />
              </Button>
            </div>
            <Input aria-label="Navigation label" value={item.label}
              onChange={(e) => patch(index, { label: e.target.value })} placeholder="Label" className="h-8 text-sm" />
            <Input aria-label="Navigation href" value={item.href}
              onChange={(e) => patch(index, { href: e.target.value })} placeholder="/ or https://" className="h-8 font-mono text-xs" />
            <Input aria-label="Navigation badge" value={item.badge ?? ""}
              onChange={(e) => patch(index, { badge: e.target.value || undefined })} placeholder="badge" className="h-8 text-sm" />
            <Button type="button" size="icon" variant="outline" className="h-8 w-8"
              onClick={() => update(items.filter((_, itemIndex) => itemIndex !== index))}
              disabled={items.length <= 1} aria-label="Remove navigation item">
              <Trash2 />
            </Button>
          </div>
          <div className="mt-2 flex flex-wrap gap-3">
            <SwitchRow label="Active" checked={item.active === true} onCheckedChange={(checked) => patch(index, { active: checked || undefined })} />
            <SwitchRow label="Disabled" checked={item.disabled === true} onCheckedChange={(checked) => patch(index, { disabled: checked || undefined })} />
            <SwitchRow label="External" checked={item.external === true} onCheckedChange={(checked) => patch(index, { external: checked || undefined })} />
          </div>
        </div>
      ))}
      <Button type="button" size="sm" variant="outline" className="h-8 text-xs"
        onClick={() => update([...items, { label: "New link", href: "/" }])}>
        <Plus /> Add nav item
      </Button>
    </div>
  );
}

function SwitchRow({ label, checked, onCheckedChange }: { label: string; checked: boolean; onCheckedChange: (checked: boolean) => void }) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
      <Switch checked={checked} onCheckedChange={onCheckedChange} />
      {label}
    </label>
  );
}

export function parseNavItems(value: string): PublicNavItem[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return [{ label: "Looking Glass", href: "/", active: true }];
    return parsed.map((item) => {
      const source = item && typeof item === "object" ? item as Record<string, unknown> : {};
      return {
        label: typeof source.label === "string" ? source.label : "",
        href: typeof source.href === "string" ? source.href : "",
        ...(source.badge ? { badge: String(source.badge) } : {}),
        ...(source.active === true ? { active: true } : {}),
        ...(source.disabled === true ? { disabled: true } : {}),
        ...(source.external === true ? { external: true } : {}),
      };
    });
  } catch {
    return [{ label: "Looking Glass", href: "/", active: true }];
  }
}
