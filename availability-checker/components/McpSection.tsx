"use client";

import { useEffect, useState } from "react";
import { Copy } from "@/components/icons";

const TOOLS: [string, string][] = [
  ["check_names", "Check a whole shortlist at once and get a ranking back"],
  ["check_name", "Full check of one name"],
  ["check_domains", "Domain availability per TLD"],
  ["suggest_domains", "Free alternative domains"],
  ["check_app_stores", "App Store and Google Play"],
  ["check_github", "GitHub handle and repo name collisions"],
  ["check_web", "Exact-phrase web search"],
  ["trademark_links", "DPMA, EUIPO, TMview, WIPO"],
];

interface Client {
  id: string;
  label: string;
  /** Where the snippet goes. */
  where?: string;
  steps?: string[];
  code?: (url: string, auth: boolean) => string;
  note?: string;
}

const TOKEN = "YOUR_TOKEN";

const CLIENTS: Client[] = [
  {
    id: "claude-code",
    label: "Claude Code",
    where: "Terminal",
    code: (u, a) =>
      `claude mcp add --transport http namevet ${u}${a ? ` \\\n  --header "Authorization: Bearer ${TOKEN}"` : ""}`,
    note: "Add --scope user to make it available in every project, or put the same URL in a .mcp.json in your project root.",
  },
  {
    id: "claude-desktop",
    label: "Claude Desktop",
    where: "claude_desktop_config.json (Settings > Developer > Edit Config), then restart",
    code: (u, a) =>
      JSON.stringify(
        {
          mcpServers: {
            "namevet": {
              command: "npx",
              args: ["-y", "mcp-remote", u, ...(a ? ["--header", "Authorization:${AUTH_HEADER}"] : [])],
              ...(a ? { env: { AUTH_HEADER: `Bearer ${TOKEN}` } } : {}),
            },
          },
        },
        null,
        2,
      ),
    note: "Needs Node.js. With a public https URL you can instead use Settings > Connectors > Add custom connector.",
  },
  {
    id: "claude-web",
    label: "claude.ai",
    steps: [
      "Deploy the app so it has a public https URL (localhost is not reachable from claude.ai).",
      "Open Settings > Connectors > Add custom connector.",
      "Name it Namevet and paste the URL below.",
      "Leave MCP_AUTH_TOKEN unset: custom connectors cannot send a static bearer token.",
    ],
    code: (u) => u,
  },
  {
    id: "codex",
    label: "Codex",
    where: "Terminal, or ~/.codex/config.toml",
    code: (u, a) =>
      a
        ? `export NAME_CHECK_TOKEN=${TOKEN}\ncodex mcp add namevet --url ${u} --bearer-token-env-var NAME_CHECK_TOKEN\n\n# or in ~/.codex/config.toml\n[mcp_servers.namevet]\nurl = "${u}"\nbearer_token_env_var = "NAME_CHECK_TOKEN"`
        : `codex mcp add namevet --url ${u}\n\n# or in ~/.codex/config.toml\n[mcp_servers.namevet]\nurl = "${u}"`,
  },
  {
    id: "gemini",
    label: "Gemini CLI",
    where: "Terminal",
    code: (u, a) =>
      `gemini mcp add --transport http namevet ${u}${a ? ` \\\n  --header "Authorization: Bearer ${TOKEN}"` : ""}`,
    note: "Writes to .gemini/settings.json in the current project. Add --scope user for all projects.",
  },
  {
    id: "cursor",
    label: "Cursor",
    where: ".cursor/mcp.json (or ~/.cursor/mcp.json)",
    code: (u, a) =>
      JSON.stringify(
        { mcpServers: { "namevet": { url: u, ...(a ? { headers: { Authorization: `Bearer ${TOKEN}` } } : {}) } } },
        null,
        2,
      ),
  },
  {
    id: "vscode",
    label: "VS Code",
    where: ".vscode/mcp.json, used by Copilot agent mode",
    code: (u, a) =>
      JSON.stringify(
        {
          servers: {
            "namevet": { type: "http", url: u, ...(a ? { headers: { Authorization: `Bearer ${TOKEN}` } } : {}) },
          },
        },
        null,
        2,
      ),
  },
  {
    id: "other",
    label: "Any other",
    where: "Any client that supports MCP over Streamable HTTP",
    code: (u) => u,
    note: "Clients that only speak stdio can bridge with: npx -y mcp-remote <url>",
  },
];

const PROMPT = "Use namevet to check these names and rank them: Assay, Plumb, Tidepool. Then show trademark links for the best two.";

export default function McpSection() {
  const [origin, setOrigin] = useState("https://your-domain.com");
  const [active, setActive] = useState(CLIENTS[0].id);
  const [auth, setAuth] = useState(false);
  const [copied, setCopied] = useState("");
  useEffect(() => setOrigin(window.location.origin), []);

  const url = `${origin}/mcp`;
  const client = CLIENTS.find((c) => c.id === active)!;
  const code = client.code?.(url, auth);

  async function copy(text: string, id: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(""), 1500);
    } catch {}
  }

  return (
    <section id="mcp" className="panel mcp">
      <div className="panel-head">
        <h2>Connect your AI agent</h2>
        <span className="muted">MCP · Streamable HTTP · {url}</span>
      </div>
      <p className="muted">Pick your tool, copy the snippet, then ask the agent to check a list of names.</p>

      <div className="tabs" role="tablist" aria-label="Agent">
        {CLIENTS.map((c) => (
          <button
            key={c.id}
            role="tab"
            aria-selected={c.id === active}
            className={c.id === active ? "tab on" : "tab"}
            onClick={() => setActive(c.id)}
          >
            {c.label}
          </button>
        ))}
      </div>

      <div className="guide" role="tabpanel">
        {client.where && <p className="small muted">{client.where}</p>}
        {client.steps && (
          <ol className="steps">
            {client.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        )}
        {code && (
          <div className="pre">
            <pre>{code}</pre>
            <button className="btn icon" onClick={() => copy(code, "code")} aria-label="Copy snippet">
              <Copy /> {copied === "code" ? "Copied" : "Copy"}
            </button>
          </div>
        )}
        {client.note && <p className="small muted">{client.note}</p>}
        {client.id !== "claude-web" && (
          <label className="check">
            <input type="checkbox" checked={auth} onChange={(e) => setAuth(e.target.checked)} />
            My server sets <code>MCP_AUTH_TOKEN</code> (adds the bearer header)
          </label>
        )}
      </div>

      <h3 className="sub-h">Then ask</h3>
      <div className="pre">
        <pre className="wrap">{PROMPT}</pre>
        <button className="btn icon" onClick={() => copy(PROMPT, "prompt")} aria-label="Copy prompt">
          <Copy /> {copied === "prompt" ? "Copied" : "Copy"}
        </button>
      </div>

      <h3 className="sub-h">Tools</h3>
      <ul className="toollist">
        {TOOLS.map(([n, d]) => (
          <li key={n}>
            <code>{n}</code>
            <span className="muted">{d}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
