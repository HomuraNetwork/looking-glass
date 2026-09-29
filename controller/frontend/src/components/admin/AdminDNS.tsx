import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface DNSFormConfig {
  base: string;
  v4Base: string;
  v6Base: string;
  singleBase: boolean;
}

interface Props {
  config: DNSFormConfig;
  onChange: (d: DNSFormConfig) => void;
  onSave: () => void;
  busy: boolean;
  /** When embedded inside a card (e.g. Integrations) drop the standalone heading/width wrapper. */
  embedded?: boolean;
}

export function AdminDNS({ config, onChange, onSave, busy, embedded = false }: Props) {
  function field(label: string, key: keyof DNSFormConfig, disabled = false) {
    return (
      <div className="space-y-1">
        <Label className="text-xs">{label}</Label>
        <Input
          value={config[key] as string}
          disabled={disabled}
          onChange={(e) => onChange({ ...config, [key]: e.target.value })}
          className="h-8 font-mono text-sm"
        />
      </div>
    );
  }

  return (
    <div className={embedded ? "space-y-4" : "max-w-md space-y-4"}>
      {!embedded && (
        <>
          <h2 className="text-base font-bold">Project DNS Settings</h2>
          <p className="text-sm text-muted-foreground">
            Base domains used when generating node DNS records automatically.
          </p>
        </>
      )}
      {field("Base domain", "base")}
      {field("IPv4 base", "v4Base", config.singleBase)}
      {field("IPv6 base", "v6Base", config.singleBase)}
      <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
        <Checkbox
          checked={config.singleBase}
          onCheckedChange={(checked) => onChange({ ...config, singleBase: checked === true })}
        />
        Single base (v4/v6 use suffixes on main base)
      </label>
      <Button onClick={onSave} disabled={busy} className="text-sm">
        Save DNS Settings
      </Button>
    </div>
  );
}
