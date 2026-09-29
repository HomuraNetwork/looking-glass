import { type ReactNode, useEffect, useRef } from "react";
import {
  LayoutDashboard, Server, Palette, Settings2, Users, Database,
  LogOut, RefreshCw, ArrowLeft, Menu,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Sheet, SheetClose, SheetContent, SheetHeader, SheetTitle, SheetTrigger,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

export type AdminSection =
  | "overview" | "nodes" | "branding" | "system" | "users" | "advanced";

interface NavItem {
  key: AdminSection;
  label: string;
  hint: string;
  icon: typeof Server;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Operate",
    items: [
      { key: "overview", label: "Overview", hint: "Status & setup", icon: LayoutDashboard },
      { key: "nodes", label: "Nodes", hint: "Probes & deploy", icon: Server },
    ],
  },
  {
    label: "Configure",
    items: [
      { key: "branding", label: "Branding", hint: "Logo, name, nav", icon: Palette },
      { key: "system", label: "System config", hint: "DNS, challenge, keys, flags", icon: Settings2 },
    ],
  },
  {
    label: "Account",
    items: [
      { key: "users", label: "Users", hint: "Admins & 2FA", icon: Users },
    ],
  },
  {
    label: "Advanced",
    items: [
      { key: "advanced", label: "Raw config", hint: "All keys, one table", icon: Database },
    ],
  },
];

const SECTION_TITLES: Record<AdminSection, string> = {
  overview: "Overview",
  nodes: "Nodes",
  branding: "Branding",
  system: "System config",
  users: "Users",
  advanced: "Raw config",
};

interface Props {
  section: AdminSection;
  onSection: (s: AdminSection) => void;
  username: string;
  siteName: string;
  busy: boolean;
  onRefresh: () => void;
  onSignOut: () => void;
  children: ReactNode;
}

export function AdminShell({
  section, onSection, username, siteName, busy, onRefresh, onSignOut, children,
}: Props) {
  const mainRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0, left: 0 });
    window.scrollTo(0, 0);
  }, [section]);

  return (
    <div className="flex h-dvh overflow-hidden bg-muted/30">
      <aside className="sticky top-0 hidden h-dvh w-60 flex-shrink-0 flex-col border-r bg-card md:flex">
        <BrandHeader siteName={siteName} />
        <nav className="flex-1 overflow-y-auto px-2 py-3">
          <NavTree section={section} onSelect={onSection} />
        </nav>
        <SidebarFooter username={username} />
      </aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 flex-shrink-0 items-center gap-3 border-b bg-card/95 px-4 backdrop-blur">
          <MobileNav section={section} onSelect={onSection} username={username} siteName={siteName} />
          <div className="min-w-0">
            <p className="truncate text-sm font-bold text-foreground">{SECTION_TITLES[section]}</p>
            <p className="truncate text-xs text-muted-foreground">{siteName} admin</p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button size="sm" variant="ghost" className="h-8 gap-1 text-xs text-muted-foreground" asChild>
              <a href="/"><ArrowLeft className="size-3.5" /> <span className="hidden sm:inline">Public LG</span></a>
            </Button>
            <Button size="sm" variant="ghost" className="h-8 w-8 px-0" onClick={onRefresh} disabled={busy}
              title="Refresh" aria-label="Refresh">
              <RefreshCw className={cn("size-4", busy && "animate-spin")} />
            </Button>
            <Button size="sm" variant="ghost" className="h-8 w-8 px-0 text-muted-foreground hover:text-destructive"
              onClick={onSignOut} title="Sign out" aria-label="Sign out">
              <LogOut className="size-4" />
            </Button>
          </div>
        </header>

        <main ref={mainRef} className="min-h-0 flex-1 overflow-auto p-4 sm:p-6">
          <div className="mx-auto max-w-6xl">{children}</div>
        </main>
      </div>
    </div>
  );
}

function BrandHeader({ siteName }: { siteName: string }) {
  return (
    <div className="flex h-14 flex-shrink-0 items-center gap-2 border-b px-4">
      <div className="flex size-7 flex-shrink-0 items-center justify-center rounded-md bg-gradient-to-br from-primary to-accent text-xs font-black text-white">
        {siteName.slice(0, 2).toUpperCase()}
      </div>
      <div className="min-w-0">
        <p className="truncate text-sm font-extrabold tracking-wide text-foreground">{siteName}</p>
        <p className="text-[0.65rem] font-semibold uppercase tracking-wider text-primary">Admin</p>
      </div>
    </div>
  );
}

function NavTree({ section, onSelect }: { section: AdminSection; onSelect: (s: AdminSection) => void }) {
  return (
    <div className="flex flex-col gap-4">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <p className="px-3 pb-1 text-[0.65rem] font-bold uppercase tracking-wider text-muted-foreground/70">
            {group.label}
          </p>
          <div className="flex flex-col gap-0.5">
            {group.items.map((item) => (
              <NavButton key={item.key} item={item} active={section === item.key}
                onClick={() => onSelect(item.key)} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function NavButton({ item, active, onClick }: { item: NavItem; active: boolean; onClick: () => void }) {
  const Icon = item.icon;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={cn(
        "group flex items-center gap-2.5 rounded-lg px-3 py-2 text-left transition-colors",
        active ? "bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
      )}
    >
      <Icon className={cn("size-4 flex-shrink-0", active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
      <span className="min-w-0">
        <span className="block text-sm font-semibold leading-tight">{item.label}</span>
        <span className="block truncate text-xs text-muted-foreground">{item.hint}</span>
      </span>
    </button>
  );
}

function SidebarFooter({ username }: { username: string }) {
  return (
    <div className="flex-shrink-0 border-t px-4 py-3">
      <div className="flex items-center gap-2">
        <div className="flex size-7 items-center justify-center rounded-full bg-muted text-xs font-bold uppercase text-muted-foreground">
          {username.slice(0, 2)}
        </div>
        <div className="min-w-0">
          <p className="truncate text-xs font-semibold text-foreground">{username}</p>
          <p className="text-[0.65rem] text-muted-foreground">Signed in</p>
        </div>
      </div>
    </div>
  );
}

function MobileNav({ section, onSelect, username, siteName }: {
  section: AdminSection; onSelect: (s: AdminSection) => void; username: string; siteName: string;
}) {
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button type="button" variant="outline" size="icon" className="size-8 md:hidden" aria-label="Open admin navigation">
          <Menu className="size-4" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-[17rem] bg-card p-0">
        <SheetHeader className="border-b px-4 py-3 text-left">
          <SheetTitle className="flex items-center gap-2 text-sm">
            <span className="flex size-6 items-center justify-center rounded-md bg-gradient-to-br from-primary to-accent text-[0.6rem] font-black text-white">{siteName.slice(0, 2).toUpperCase()}</span>
            {siteName} Admin
          </SheetTitle>
        </SheetHeader>
        <nav className="px-2 py-3">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="mb-3">
              <p className="px-3 pb-1 text-[0.65rem] font-bold uppercase tracking-wider text-muted-foreground/70">{group.label}</p>
              <div className="flex flex-col gap-0.5">
                {group.items.map((item) => (
                  <SheetClose asChild key={item.key}>
                    <NavButton item={item} active={section === item.key} onClick={() => onSelect(item.key)} />
                  </SheetClose>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <Separator />
        <div className="px-4 py-3 text-xs text-muted-foreground">Signed in as <span className="font-semibold text-foreground">{username}</span></div>
      </SheetContent>
    </Sheet>
  );
}
