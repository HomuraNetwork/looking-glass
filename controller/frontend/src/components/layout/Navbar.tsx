import { memo } from "react";
import { Moon, Sun, ExternalLink, Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { type Theme, type ThemePreference } from "@/lib/theme";
import type { PublicNavItem } from "@/lib/api";
import { safeNavHref } from "@/lib/nav-url";
import { cn } from "@/lib/utils";

interface Props {
  theme: ThemePreference;
  resolvedTheme: Theme;
  onToggleTheme: () => void;
  isAdmin?: boolean;
  siteName?: string;
  logoText?: string;
  logoImageUrl?: string | null;
  brandName?: string;
  showBrandName?: boolean;
  navItems?: PublicNavItem[];
}

const fallbackNavItems: PublicNavItem[] = [
  { label: "Looking Glass", href: "/", active: true },
];

export const Navbar = memo(function Navbar({ theme, resolvedTheme, onToggleTheme, isAdmin = false, siteName = "Looking Glass", logoText = "LG", logoImageUrl = null, brandName = "", showBrandName = false, navItems = fallbackNavItems }: Props) {
  const visibleNavItems = navItems.length > 0 ? navItems : fallbackNavItems;
  return (
    <nav
      className="sticky top-0 z-40 flex h-[var(--nav-height)] flex-shrink-0 items-center gap-3 border-b border-border/70 bg-background/80 px-4 backdrop-blur-md supports-[backdrop-filter]:bg-background/60"
    >
      <a href="/" className="flex min-w-0 flex-1 items-center gap-2.5 no-underline md:flex-none">
        {logoImageUrl ? (
          <img
            src={logoImageUrl}
            alt={brandName || siteName}
            className="h-6 w-auto max-w-[7rem] flex-shrink-0 object-contain object-left sm:max-w-[10rem]"
            onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }}
          />
        ) : (
          <div className="flex size-6 flex-shrink-0 items-center justify-center rounded-lg bg-primary text-xs font-black text-primary-foreground shadow-sm">
            {logoText.slice(0, 3)}
          </div>
        )}
        {siteName && (
          <>
            {logoImageUrl && <span aria-hidden className="h-4 w-px flex-shrink-0 bg-border" />}
            <span className="min-w-0 truncate text-sm font-bold tracking-tight text-foreground">
              {showBrandName && brandName ? `${brandName} ${siteName}` : siteName}
            </span>
          </>
        )}
        {isAdmin && <span className="ml-1 flex-shrink-0 text-xs font-medium text-muted-foreground">· Admin</span>}
      </a>

      {!isAdmin && (
        <div className="hidden h-full items-stretch md:flex">
          {visibleNavItems.map((item) => (
            <NavItem key={`${item.label}:${item.href}`} item={item} />
          ))}
        </div>
      )}

      <div className="ml-auto hidden items-center gap-2 md:flex">
        <ThemeButton theme={theme} resolvedTheme={resolvedTheme} onToggleTheme={onToggleTheme} />
      </div>

      {!isAdmin && (
        <div className="ml-auto flex items-center gap-2 md:hidden">
          <ThemeButton theme={theme} resolvedTheme={resolvedTheme} onToggleTheme={onToggleTheme} />
          <MobileNav items={visibleNavItems} siteName={siteName} />
        </div>
      )}
    </nav>
  );
});

function NavItem({ item }: { item: PublicNavItem }) {
  const href = safeNavHref(item.href);
  return (
    <a
      href={item.disabled || !href ? undefined : href}
      target={item.external ? "_blank" : undefined}
      rel={item.external ? "noreferrer" : undefined}
      className={cn(
        "flex items-center gap-1.5 border-b-2 px-3.5 text-sm font-medium no-underline transition-colors",
        item.active
          ? "border-primary text-foreground font-semibold"
          : "border-transparent text-muted-foreground hover:border-border/70 hover:text-foreground",
        item.disabled && "cursor-default opacity-60",
      )}
    >
      {item.label}
      {item.external && <ExternalLink className="size-3 opacity-60" />}
      {item.badge && (
        <span className="rounded-full border border-primary/20 bg-primary/10 px-1.5 py-px font-mono text-[0.6875rem] font-bold text-primary">
          {item.badge}
        </span>
      )}
    </a>
  );
}

function MobileNav({ items, siteName }: { items: PublicNavItem[]; siteName: string }) {
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button
          type="button"
          variant="outline"
          size="icon"
          className="size-8 flex-shrink-0 rounded-lg border border-border/70 bg-muted/20 text-muted-foreground hover:bg-muted hover:text-foreground active:scale-95"
          aria-label="Open navigation"
        >
          <Menu className="size-4" />
        </Button>
      </SheetTrigger>
      <SheetContent side="right" className="w-[min(20rem,calc(100vw-2rem))] border-l bg-card p-0 text-card-foreground">
        <SheetHeader className="border-b px-4 py-3 text-left">
          <SheetTitle className="font-mono text-sm">{siteName}</SheetTitle>
        </SheetHeader>
        <div className="flex flex-col gap-1 p-2">
          {items.map((item) => (
            <MobileNavItem key={`${item.label}:${item.href}`} item={item} />
          ))}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function MobileNavItem({ item }: { item: PublicNavItem }) {
  const href = safeNavHref(item.href);
  const content = (
    <span
      className={cn(
        "flex min-h-10 items-center justify-between gap-3 rounded-lg px-3 text-sm font-medium no-underline transition-colors",
        item.active ? "bg-primary/10 text-primary font-semibold" : "text-foreground hover:bg-muted",
        item.disabled && "cursor-default opacity-50",
      )}
    >
      <span className="min-w-0 truncate">
        {item.label}
      </span>
      <span className="flex flex-shrink-0 items-center gap-1.5">
        {item.badge && (
          <span className="rounded-full border bg-muted px-1.5 py-px font-mono text-xs text-muted-foreground">
            {item.badge}
          </span>
        )}
        {item.external && <ExternalLink className="size-3 opacity-60" />}
      </span>
    </span>
  );
  if (item.disabled || item.active || !href) return content;
  return (
    <SheetClose asChild>
      <a
        href={href}
        target={item.external ? "_blank" : undefined}
        rel={item.external ? "noreferrer" : undefined}
        className="no-underline"
      >
        {content}
      </a>
    </SheetClose>
  );
}

function ThemeButton({ resolvedTheme, onToggleTheme }: { theme?: ThemePreference; resolvedTheme: Theme; onToggleTheme: () => void }) {
  const isDark = resolvedTheme === "dark";
  const title = isDark ? "Switch to light theme" : "Switch to dark theme";

  return (
    <Button
      type="button"
      variant="outline"
      size="icon"
      onClick={onToggleTheme}
      className="flex size-8 flex-shrink-0 items-center justify-center rounded-lg border border-border/70 bg-muted/20 text-muted-foreground transition-all duration-150 hover:bg-muted hover:text-foreground active:scale-95"
      title={title}
      aria-label={title}
    >
      {isDark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </Button>
  );
}
