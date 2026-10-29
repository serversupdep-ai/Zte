import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import Logo from "@/components/Logo";

export const metadata: Metadata = {
  title: "Namevet",
  description: "Check domains, app stores, web and trademark registers for a product name, from the browser or via MCP.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="glow" aria-hidden />
        <header className="nav">
          <Link href="/" className="brand">
            <Logo />
            Namevet
          </Link>
          <nav>
            <Link href="/#mcp">Use with AI</Link>
            <Link href="/#skill">Skill</Link>
          </nav>
        </header>
        {children}
        <footer className="foot">
          <span>Namevet · a first screen, not legal advice</span>
          <Link href="/impressum">Impressum</Link>
        </footer>
      </body>
    </html>
  );
}
