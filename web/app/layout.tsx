import type { Metadata } from "next";
import "@fontsource-variable/geist";
import "./globals.css";
import "./workspace.css";
import "./studio.css";
import "./controls.css";
import { Shell } from "../components/shell";

export const metadata: Metadata = {
  title: {
    default: "Security overview | Guardrail",
    template: "%s | Guardrail",
  },
  description:
    "Explore synthetic agent runs and recorded MCP security evidence.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
