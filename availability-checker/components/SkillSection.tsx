"use client";

import { useEffect, useState } from "react";
import { Copy } from "@/components/icons";

interface Target {
  id: string;
  label: string;
  where: string;
  code: (origin: string) => string;
  note?: string;
}

const REPO = "MikaStiebitz/Namevet";

const TARGETS: Target[] = [
  {
    id: "npx",
    label: "Any agent (npx)",
    where: "Terminal. Detects your installed agents and asks where to put it.",
    code: () => `npx skills add ${REPO}`,
  },
  {
    id: "claude",
    label: "Claude Code",
    where: "Terminal, installs for all your projects",
    code: (o) => `curl -fsSL ${o}/skill.md --create-dirs -o ~/.claude/skills/creative-naming/SKILL.md`,
    note: "Use .claude/skills/creative-naming/SKILL.md inside a project to install it for that project only.",
  },
  {
    id: "agents",
    label: "Codex / Gemini CLI",
    where: "Terminal, ~/.agents/skills is read by both",
    code: (o) => `curl -fsSL ${o}/skill.md --create-dirs -o ~/.agents/skills/creative-naming/SKILL.md`,
    note: "Also works at ~/.codex/skills (Codex) and ~/.gemini/skills (Gemini CLI).",
  },
  {
    id: "manual",
    label: "Manual",
    where: "Any agent that supports SKILL.md",
    code: () => "creative-naming/\n  SKILL.md   <- download it below",
    note: "Put the folder in your agent's skills directory. For Claude Desktop or claude.ai, zip the creative-naming folder and upload it under Settings > Capabilities > Skills.",
  },
];

export default function SkillSection() {
  const [origin, setOrigin] = useState("https://your-domain.com");
  const [active, setActive] = useState(TARGETS[0].id);
  const [copied, setCopied] = useState("");
  useEffect(() => setOrigin(window.location.origin), []);

  const target = TARGETS.find((t) => t.id === active)!;
  const code = target.code(origin);

  async function copy(text: string, id: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(""), 1500);
    } catch {}
  }

  async function copySkill() {
    try {
      await copy(await (await fetch("/skill.md")).text(), "skill");
    } catch {}
  }

  return (
    <section id="skill" className="panel mcp">
      <div className="panel-head">
        <h2>Add the naming skill</h2>
        <span className="muted">creative-naming · SKILL.md</span>
      </div>
      <p className="muted">
        Teaches your agent to invent names that do not read like generated slop (no -ly, -ify, Nova or Lumora-style mashups), then vet
        them with Namevet before recommending anything. Works best together with the MCP server above.
      </p>

      <div className="tabs" role="tablist" aria-label="Install method">
        {TARGETS.map((t) => (
          <button key={t.id} role="tab" aria-selected={t.id === active} className={t.id === active ? "tab on" : "tab"} onClick={() => setActive(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <div className="guide" role="tabpanel">
        <p className="small muted">{target.where}</p>
        <div className="pre">
          <pre>{code}</pre>
          <button className="btn icon" onClick={() => copy(code, "code")} aria-label="Copy command">
            <Copy /> {copied === "code" ? "Copied" : "Copy"}
          </button>
        </div>
        {target.note && <p className="small muted">{target.note}</p>}
        <div className="row">
          <a className="btn" href="/skill.md" download="SKILL.md">
            Download SKILL.md
          </a>
          <button className="btn" onClick={copySkill}>
            <Copy /> {copied === "skill" ? "Copied" : "Copy skill text"}
          </button>
          <a className="btn" href="/skill.md" target="_blank" rel="noreferrer">
            Preview
          </a>
        </div>
      </div>

      <h3 className="sub-h">Then ask</h3>
      <div className="pre">
        <pre className="wrap">Invent names for a privacy-first note app. Use creative-naming.</pre>
        <button className="btn icon" onClick={() => copy("Invent names for a privacy-first note app. Use creative-naming.", "prompt")} aria-label="Copy prompt">
          <Copy /> {copied === "prompt" ? "Copied" : "Copy"}
        </button>
      </div>
    </section>
  );
}
