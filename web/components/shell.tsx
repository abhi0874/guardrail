"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  Activity,
  Blocks,
  ChevronRight,
  Files,
  Fingerprint,
  History,
  Layers3,
  LayoutDashboard,
  Menu,
  ScanLine,
  ShieldCheck,
  SquareTerminal,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

const groups: [string, [string, string, LucideIcon][]][] = [
  [
    "Workspace",
    [
      ["/", "Overview", LayoutDashboard],
      ["/playground/", "Agent Playground", SquareTerminal],
      ["/scanner/", "Security Scanner", ScanLine],
      ["/findings/", "Findings", Fingerprint],
      ["/history/", "Execution History", History],
    ],
  ],
  [
    "Evidence library",
    [
      ["/tools/", "MCP tools", Blocks],
      ["/tests/", "Security tests", Layers3],
      ["/audit/", "Audit evidence", Files],
      ["/performance/", "Performance", Activity],
    ],
  ],
];

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname().replace(/\/$/, "") + "/";
  const [open, setOpen] = useState(false);
  const matches = (href: string) =>
    path === href ||
    (href !== "/" && path.startsWith(href)) ||
    (href === "/tests/" && path.startsWith("/attacks/"));
  const current =
    groups.flatMap(([, items]) => items).find(([href]) => matches(href))?.[1] ??
    "Recorded dashboard";
  useEffect(() => {
    if (!open) return;
    function dismiss(event: KeyboardEvent) {
      if (event.key === "Escape" && !document.querySelector("dialog:modal")) {
        setOpen(false);
        document.getElementById("menu-toggle")?.focus();
      }
    }
    document.addEventListener("keydown", dismiss);
    return () => document.removeEventListener("keydown", dismiss);
  }, [open]);
  return (
    <div className="frame">
      <a className="skip" href="#main" tabIndex={0}>
        Skip to content
      </a>
      <aside className={open ? "sidebar expanded" : "sidebar"}>
        <div className="brand-line">
          <Link
            className="brand"
            href="/"
            tabIndex={0}
            onClick={() => setOpen(false)}
          >
            <span className="brandmark">
              <Fingerprint />
            </span>
            Guardrail
          </Link>
          <button
            id="menu-toggle"
            className="icon-btn mobile"
            aria-label={open ? "Close navigation" : "Open navigation"}
            aria-controls="side-nav"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            {open ? <X /> : <Menu />}
          </button>
        </div>
        <nav id="side-nav" aria-label="Workspace">
          {groups.map(([label, items]) => (
            <div className="nav-group" key={label}>
              <span className="nav-label">{label}</span>
              {items.map(([href, name, Icon]) => (
                <Link
                  key={href}
                  href={href}
                  className="nav-item"
                  tabIndex={0}
                  aria-current={matches(href) ? "page" : undefined}
                  onClick={() => setOpen(false)}
                >
                  <Icon />
                  {name}
                </Link>
              ))}
            </div>
          ))}
        </nav>
        <div className="side-foot">
          <ShieldCheck />
          <div>
            <strong>MCP Agent Server</strong>
            <small>Recorded dashboard</small>
          </div>
        </div>
      </aside>
      <div className="work">
        <header className="top">
          <div className="crumb">
            <Layers3 />
            <span>Workspace</span>
            <ChevronRight size={13} />
            <b>{current}</b>
          </div>
          <div className="top-right">
            <span>Recorded edition</span>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
