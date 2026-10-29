"use client";

import { useState } from "react";
import type { FullCheck } from "@/lib/check";
import type { Suggestion } from "@/lib/suggest";
import { summarize } from "@/lib/score";
import { Arrow, Globe, Phone, Scale, Search, Spark } from "@/components/icons";

const WORD: Record<string, string> = { available: "free", taken: "taken", unknown: "unknown", exact: "name in use", similar: "similar names", none: "clear", error: "check failed" };
const KIND: Record<string, string> = { available: "ok", taken: "bad", unknown: "warn", exact: "bad", similar: "warn", none: "ok", error: "warn" };

function Tag({ v }: { v: string }) {
  return <span className={`tag ${KIND[v]}`}>{WORD[v]}</span>;
}

export default function NameCard({ name, data, error }: { name: string; data?: FullCheck; error?: string }) {
  const [sugg, setSugg] = useState<Suggestion[] | null>(null);
  const [loading, setLoading] = useState(false);

  async function suggest() {
    setLoading(true);
    try {
      setSugg((await (await fetch(`/api/suggest?name=${encodeURIComponent(name)}`)).json()).suggestions ?? []);
    } catch {
      setSugg([]);
    }
    setLoading(false);
  }

  if (error)
    return (
      <article className="card">
        <h2 className="name">{name}</h2>
        <p className="err">{error}</p>
      </article>
    );
  if (!data)
    return (
      <article className="card" aria-busy="true">
        <h2 className="name">{name}</h2>
        <div className="skel"><i /><i /><i /></div>
      </article>
    );

  const s = summarize(data);
  const [apple, play] = data.stores;

  return (
    <article className="card">
      <header className="card-head">
        <h2 className="name">{name}</h2>
        <div className="score">
          <span className={`ring ${s.verdict}`}>{s.score}</span>
          <span className="muted">
            {s.verdict === "promising" ? "Looks promising" : s.verdict === "mixed" ? "Mixed" : "Crowded"}
          </span>
        </div>
      </header>

      <div className="bento">
        <section className="box wide">
          <h3><Globe /> Domains <span className="count">{s.domainsFree.length}/{data.domains.length} free</span></h3>
          <div className="tiles">
            {data.domains.map((d) => (
              <a
                key={d.domain}
                className={`tile ${KIND[d.status]}`}
                href={d.status === "available" ? d.registerUrl : `https://${d.domain}`}
                target="_blank"
                rel="noreferrer"
                title={d.registrar ? `${d.registrar}${d.expires ? ` · expires ${d.expires}` : ""}` : undefined}
              >
                <b>{d.domain}</b>
                <span>{WORD[d.status]}{d.method === "dns" ? " · dns guess" : ""}</span>
              </a>
            ))}
          </div>
          <div className="row">
            <button className="btn" onClick={suggest} disabled={loading}>
              <Spark /> {loading ? "Searching…" : "Suggest free alternatives"}
            </button>
            <span className="muted small">“dns guess” = TLD without RDAP; confirm at a registrar.</span>
          </div>
          {sugg && (
            <div className="tiles sugg">
              {sugg.length === 0 && <span className="muted">No free variants found.</span>}
              {sugg.map((x) => (
                <a key={x.domain} className="tile ok" href={x.registerUrl} target="_blank" rel="noreferrer">
                  <b>{x.domain}</b>
                  <span>{x.kind}</span>
                </a>
              ))}
            </div>
          )}
        </section>

        <section className="box">
          <h3><Phone /> App stores</h3>
          {[apple, play].map((st) => (
            <div className="store" key={st.store}>
              <div className="store-head">
                <b>{st.store === "app-store" ? "App Store" : "Google Play"}</b>
                <Tag v={st.verdict} />
              </div>
              {st.error && <p className="err small">{st.error}</p>}
              <ul className="list">
                {st.hits.slice(0, 3).map((h) => (
                  <li key={h.url}>
                    <a href={h.url} target="_blank" rel="noreferrer">{h.title}</a>
                    <span className="muted"> · {h.developer}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </section>

        <section className="box">
          <h3><Search /> Web</h3>
          {data.web.provider === "links" ? (
            <p className="muted small">No search API key set, so these open the searches in a new tab.</p>
          ) : (
            <>
              {data.web.totalResults !== undefined && <p className="small">About {data.web.totalResults.toLocaleString()} results for {data.web.query}</p>}
              <ul className="list">
                {data.web.hits.map((h) => (
                  <li key={h.url}><a href={h.url} target="_blank" rel="noreferrer">{h.title}</a></li>
                ))}
              </ul>
            </>
          )}
          {data.web.error && <p className="err small">{data.web.error}</p>}
          <div className="links">
            {data.web.links.map((l) => (
              <a key={l.url} className="pill" href={l.url} target="_blank" rel="noreferrer">{l.label} <Arrow /></a>
            ))}
          </div>
        </section>

        <section className="box wide">
          <h3><Scale /> Trademark registers <span className="count">Nice classes {data.trademarks.classes.map((c) => c.n).join(", ")}</span></h3>
          <div className="regs">
            {data.trademarks.links.map((l) => (
              <a key={l.id} className="reg" href={l.url} target="_blank" rel="noreferrer">
                <b>{l.label} <Arrow /></b>
                <span>{l.note}</span>
              </a>
            ))}
          </div>
        </section>
      </div>
    </article>
  );
}
