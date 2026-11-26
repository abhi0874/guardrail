"use client";
import { useSyncExternalStore } from "react";
function subscribe(callback: () => void) {
  window.addEventListener("popstate", callback);
  return () => window.removeEventListener("popstate", callback);
}
export function ReturnLink({ path, label }: { path: string; label: string }) {
  const suffix = useSyncExternalStore(
    subscribe,
    () => location.search,
    () => "",
  );
  return (
    <a className="back" href={path + suffix}>
      {label}
    </a>
  );
}
